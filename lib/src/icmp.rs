use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::os::fd::FromRawFd;
use std::os::unix::net;

use mio::net::UnixStream;
use pnet::packet::icmp::{IcmpPacket, IcmpType};

use crate::flow::{flow_initiate_af, FlowType, Flowside, PifType, StateIdx, FLOWATSIDX, FLOWS};
use crate::fwd::fwd_nat_from_tap;
use crate::socket::{create_socket, set_socketopt, sockaddr_in_from};
use mio::{Interest, Registry, Token};
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum IcmpError {
    BindError(i32),
    NotEchoError,
    EpollError(String),
}

impl std::fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpError::BindError(e) => write!(
                f,
                "Failed to bind to the created icmp socket with status: {}",
                e
            ),
            IcmpError::NotEchoError => write!(f, "Packet is not an echo packet"),
            IcmpError::EpollError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for IcmpError {}

pub fn handle_icmp_packet(reg: &Registry, v4packet: Ipv4Packet) -> Result<(), IcmpError> {
    // should a table of flows and a table of indexes
    // build the flowside from the icmp packet data
    // i need to store the source and dest ips before turning it to an icmp packet
    let src = v4packet.get_source();
    let dest = v4packet.get_destination();
    let icmp_packet = IcmpPacket::owned(v4packet.payload().to_owned()).unwrap();

    // is there a constant type i can compare with instead of this ?
    if icmp_packet.get_icmp_type() != IcmpType::new(8) {
        return Err(IcmpError::NotEchoError);
    }

    // SAFETY: we know that its an echo because we checked above
    // so ID is certainly there
    let arr = unsafe { *(icmp_packet.payload().as_ptr() as *const [u8; 4]) };

    let id = u16::from_be_bytes([arr[0], arr[1]]);

    let flowside = Flowside::new(src, dest, id, id);
    // get the sidx (the flow table index) from the flowside
    if let Some(sidx) = FLOWATSIDX.read().unwrap().get(&flowside) {
        let f = unsafe { FLOWS.flows[sidx.flow_table_idx] };
        // nil check for f or flow init
        new_icmp_flow(reg, src, dest, id, id)?;
    };

    // check if the flow matches the flowside structrue we built in address and port, no port in icmp ?
    // we use the id field in the icmp header for src/dst port
    // then we need to turn the packet to an icmp packet?
    Ok(())
}

pub fn new_icmp_flow(
    registry: &Registry,
    src: Ipv4Addr,
    dest: Ipv4Addr,
    srcport: u16,
    destport: u16,
) -> Result<(), IcmpError> {
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
    let socket_addr = sockaddr_in_from(&f.side[1].src, f.side[1].srcport);
    let fd = create_socket(
        libc::AF_INET,
        libc::SOCK_DGRAM,
        libc::SA_NOCLDSTOP, // is there no sock nonblock on bsd/ios ? should be non block
        libc::IPPROTO_ICMP,
    )
    .unwrap();

    let opt_val = 1;

    set_socketopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        opt_val,
        std::mem::size_of_val(&opt_val),
    );

    let bind_result = unsafe {
        libc::bind(
            fd,
            &socket_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&socket_addr) as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        return Err(IcmpError::BindError(bind_result));
    }

    // not sure if this insert maps to whats really in the c code
    FLOWATSIDX.write().unwrap().insert(f.side[1], sidx);

    let mut s = unsafe { UnixStream::from_std(net::UnixStream::from_raw_fd(fd)) };

    // call epoll ctl
    registry
        .register(&mut s, Token(fd as usize), Interest::READABLE)
        .map_err(|e| IcmpError::EpollError(e.to_string()))?;
    Ok(())
}
