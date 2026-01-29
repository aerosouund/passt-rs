use std::fmt;
use std::net::Ipv4Addr;
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
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;

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
    SendPacketError(usize),
}

impl std::fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpError::SysError(e) => write!(
                f,
                "Failed to bind to the created icmp socket with status: {}",
                e
            ),
            IcmpError::NotEchoError => write!(f, "Packet is not an echo packet"),
            IcmpError::EpollError(e) => write!(f, "IO error: {}", e),
            IcmpError::InvalidSidxError => write!(f, "invalid state index built from packet"),
            Self::SendPacketError(errno) => {
                write!(f, "send to socket errored with number: {}", errno)
            }
        }
    }
}

impl From<Errno> for IcmpError {
    fn from(value: Errno) -> Self {
        IcmpError::SysError(value as i32)
    }
}

impl std::error::Error for IcmpError {}

pub fn handle_icmp_packet(
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

    let mut flow = FLOWS.flows[sidx];

    // Will hold return value only if we initialized
    let mut new_conn: Option<(Token, ConnEnum)> = None;

    // Initialize flow if needed
    if flow == Flow::default() {
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
        MsgFlags::MSG_CTRUNC, // should be nosignal
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
    let nextfree = unsafe { FLOWS.next_free };
    let mut f = unsafe { FLOWS.flows[FLOWS.next_free] };
    let mut ini_f = flow_initiate_af(&mut f, src, dest, srcport, destport, PifType::Host);

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
