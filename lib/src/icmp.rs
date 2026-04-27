use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net;

use mio::net::UnixStream;
use mio::{Interest, Registry, Token};

use nix::errno::Errno;
use nix::sys::socket::{
    MsgFlags, SockFlag, SockProtocol, SockaddrIn, bind, sendto, setsockopt, socket, sockopt,
};

use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::ndp::{
    MutableNeighborAdvertPacket, MutableRouterAdvertPacket, NdpOption, NdpOptionTypes,
    NeighborSolicitPacket,
};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

use crate::Conf;
use crate::flow::{
    FLOWATSIDX, FLOWS, Flow, FlowType, Flowside, PifType, StateIdx, flow_initiate_af,
};
use crate::fwd::fwd_nat_from_tap;
use crate::muxer::{ConnEnum, StreamConnCtx};

#[derive(Debug)]
pub enum IcmpError {
    SysError(i32),
    NotEchoError,
    EpollError(String),
    InvalidSidxError,
}

impl std::fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpError::SysError(e) => write!(f, "sys error, status: {}", e),
            IcmpError::NotEchoError => write!(f, "Packet is not an echo packet"),
            IcmpError::EpollError(e) => write!(f, "IO error: {}", e),
            IcmpError::InvalidSidxError => write!(f, "invalid state index built from packet"),
        }
    }
}

impl From<Errno> for IcmpError {
    fn from(value: Errno) -> Self {
        IcmpError::SysError(value as i32)
    }
}

impl std::error::Error for IcmpError {}

pub fn handle_icmp6_packet(conf: &Conf, v6packet: Ipv6Packet<'static>) -> Result<(), IcmpError> {
    let src = v6packet.get_source();
    let dest = v6packet.get_destination();
    let icmp_packet = Icmpv6Packet::owned(v6packet.payload().to_owned()).unwrap();
    match icmp_packet.get_icmpv6_type() {
        Icmpv6Types::NeighborSolicit => {
            let ns_packet = NeighborSolicitPacket::owned(icmp_packet.payload().to_owned()).unwrap();
            ndp_na(conf, dest, ns_packet.get_target_addr())
        }
        Icmpv6Types::RouterSolicit => ndp_ra(conf, dest),
        // treat this as a normal icmp packet
        _ => Err(IcmpError::SysError(5)),
    }
}

pub fn handle_icmp4_packet(
    reg: &Registry,
    v4packet: Ipv4Packet,
) -> Result<Option<(Token, ConnEnum)>, IcmpError> {
    // should a table of flows and a table of indexes
    // build the flowside from the icmp packet data
    let src = v4packet.get_source();
    let dest = v4packet.get_destination();
    let icmp_packet = IcmpPacket::owned(v4packet.payload().to_owned()).unwrap();

    if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
        return Err(IcmpError::NotEchoError);
    }
    // SAFETY: we know that its an echo because we checked above
    // so ID is certainly there
    let arr = unsafe { *(icmp_packet.payload().as_ptr() as *const [u8; 4]) };

    let id = u16::from_be_bytes([arr[0], arr[1]]);

    let flowside = Flowside::new(src, dest, id, id);
    // get the sidx (the flow table index) from the flowside
    let sidx = {
        let guard = FLOWATSIDX.read().unwrap();
        guard
            .get(&flowside)
            .expect("missing flowside")
            .flow_table_idx
    };

    let flow = &mut FLOWS.write().unwrap().flows[sidx];

    // Will hold return value only if we initialized
    let mut new_conn: Option<(Token, ConnEnum)> = None;

    // Initialize flow if needed
    if *flow == Flow::default() {
        let fd = new_icmp_flow(src, dest, id, id)?;

        let mut s = unsafe { UnixStream::from_std(net::UnixStream::from_raw_fd(fd)) };

        reg.register(&mut s, Token(fd as usize), Interest::READABLE)
            .map_err(|e| IcmpError::EpollError(e.to_string()))?;

        flow.ping = crate::flow::Ping { socket_fd: fd };
        flow.flow_common.flow_state = crate::flow::FlowState::Active;

        new_conn = Some((
            Token(fd as usize),
            ConnEnum::Stream(StreamConnCtx {
                stream: s,
                partial_frame: Vec::new(),
            }),
        ));
    }

    // build sockaddr
    let [a, b, c, d] = flow.side[1].dest.octets();
    let addr = SockaddrIn::new(a, b, c, d, 0);

    // send packet
    sendto(
        flow.ping.socket_fd,
        v4packet.payload(),
        &addr,
        MsgFlags::MSG_NOSIGNAL,
    )?;
    Ok(new_conn)
}

// this function should return a pif
// and then we call pif socketaddr
pub fn new_icmp_flow(
    src: Ipv4Addr,
    dest: Ipv4Addr,
    srcport: u16,
    destport: u16,
) -> Result<RawFd, IcmpError> {
    // stupid ass asserts
    //
    let nextfree = FLOWS.read().unwrap().next_free;
    let f = &mut FLOWS.write().unwrap().flows[nextfree];
    let mut ini_f = flow_initiate_af(f, src, dest, srcport, destport, PifType::Host);

    match f.flow_common.pif[0] {
        PifType::Tap => {
            // fwd_nat_from_tap
            let target_pif = fwd_nat_from_tap(
                IpNextHeaderProtocols::Icmp,
                &mut ini_f,
                &mut f.side[1],
                srcport,
            );
            f.flow_common.pif[1] = target_pif
        }
        PifType::Host => {
            // fwd_nat_from_host
        }
        PifType::Splice => {
            // fwd_nat_from_splice
        }
        _ => {}
    }
    if f.flow_common.pif[1] != PifType::Host {
        // error
    }
    f.flow_common.flow_type = FlowType::Ping;
    // initiaite flow sidx
    let sidx = StateIdx {
        sidei: 1,
        flow_table_idx: nextfree,
    };

    // build a socket address from the given data
    let [a, b, c, d] = f.side[1].src.octets();
    let addr = SockaddrIn::new(a, b, c, d, 0);
    let fd = socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        SockProtocol::Icmp,
    )?;

    let opt_val: bool = true;

    setsockopt(&fd, sockopt::ReuseAddr, &opt_val)?;
    bind(fd.as_raw_fd(), &addr)?;

    FLOWATSIDX.write().unwrap().insert(f.side[1], sidx);
    Ok(fd.as_raw_fd())
    // not sure if this insert maps to whats really in the c code
}

fn ndp_na(conf: &Conf, dest: Ipv6Addr, addr: Ipv6Addr) -> Result<(), IcmpError> {
    // 8 is an arbitrary number for the option length. we need to verify that
    let mut na_buf = vec![0u8; MutableNeighborAdvertPacket::minimum_packet_size() + 8];
    let mut neighbor_adv = MutableNeighborAdvertPacket::new(&mut na_buf).unwrap();

    neighbor_adv.set_target_addr(addr);
    let l2_opt = NdpOption {
        option_type: NdpOptionTypes::TargetLLAddr,
        length: 1,
        data: conf.tap_mac.to_vec(),
    };
    neighbor_adv.set_options(&[l2_opt]);
    neighbor_adv.set_flags(0b111); // R=1, S=1, O=1

    let mut v6_packet_vec =
        vec![0u8; MutableIpv6Packet::minimum_packet_size() + neighbor_adv.packet().len()];

    let mut v6reply = MutableIpv6Packet::new(&mut v6_packet_vec).unwrap();
    v6reply.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6reply.set_payload_length(neighbor_adv.packet().len() as u16);
    v6reply.set_payload(neighbor_adv.packet());
    v6reply.set_source(conf.ip6.our_tap_ll);
    v6reply.set_destination(dest);

    Ok(())
}

fn ndp_ra(conf: &Conf, dest: Ipv6Addr) -> Result<(), IcmpError> {
    let mut prefix_opt_data = Vec::with_capacity(32);
    prefix_opt_data.push(64);
    prefix_opt_data.push(0xC0);
    prefix_opt_data.extend_from_slice(&u32::MAX.to_be_bytes());
    prefix_opt_data.extend_from_slice(&u32::MAX.to_be_bytes());
    prefix_opt_data.extend_from_slice(&0u32.to_be_bytes());
    prefix_opt_data.extend_from_slice(&conf.ip6.addr.octets());

    // build the options vector
    let options = [
        NdpOption {
            option_type: NdpOptionTypes::PrefixInformation,
            length: 4,
            data: prefix_opt_data,
        },
        NdpOption {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: conf.tap_mac.to_vec(),
        },
    ];
    // 32 and eight are two constants we are unsure of, they are the theoretical size of the
    // prefix opt (32) and the source link local opt (8). we need to verify them though
    let mut buf = vec![0u8; MutableRouterAdvertPacket::minimum_packet_size() + 32 + 8];
    let mut router_adv = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    router_adv.set_hop_limit(255);
    router_adv.set_options(&options);

    let mut v6_packet_vec =
        vec![0u8; MutableIpv6Packet::minimum_packet_size() + router_adv.packet().len()];

    let mut v6reply = MutableIpv6Packet::new(&mut v6_packet_vec).unwrap();
    v6reply.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6reply.set_payload_length(router_adv.packet().len() as u16);
    v6reply.set_payload(router_adv.packet());
    v6reply.set_source(conf.ip6.our_tap_ll);
    v6reply.set_destination(dest);

    // perform actual sending
    Ok(())
}
