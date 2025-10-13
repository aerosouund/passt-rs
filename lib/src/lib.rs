use libc::in_addr;
use mio::net::UnixStream;
use nix::sys::socket::{recv, MsgFlags};
use pnet::packet::arp;
use pnet::packet::arp::Arp;
use pnet::packet::arp::ArpOperation;
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes::Arp;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use tokio::sync::mpsc::Sender;

pub const MAX_FRAME: usize = 65535 + 4;

#[derive(Default)]
pub struct Context {
    pub debug: i32,
    pub trace: i32,
    pub stream: Option<UnixStream>,
    pub stream_fd: RawFd,
    pub partial_tap_frame: Vec<u8>,
}

impl Context {
    pub fn new() -> Self {
        Context {
            debug: 0,
            trace: 0,
            partial_tap_frame: Vec::with_capacity(65535),
            ..Default::default()
        }
    }
}

pub struct PartialFrame(pub Vec<u8>);

pub async fn handle_packets(
    tx: &Sender<EthernetPacket<'static>>,
    packets: &mut Vec<EthernetPacket<'static>>,
) {
    for p in packets.drain(..) {
        if p.get_ethertype() == Arp {
            if let Some(final_packet) = handle_arp_packet(&mut p.packet().to_vec()) {
                match tx.send(final_packet).await {
                    Ok(()) => {}
                    Err(e) => {}
                }
            }
        };
    }
}

fn handle_arp_packet(packet_data: &mut Vec<u8>) -> Option<EthernetPacket<'static>> {
    let mut arp_packet = MutableArpPacket::new(packet_data.as_mut_slice()).unwrap();
    if arp_packet.get_sender_proto_addr() == arp_packet.get_target_proto_addr() {
        return None;
    }

    // swap sender and target ip
    let sender_ip = arp_packet.get_sender_proto_addr();
    let target_tp = arp_packet.get_target_proto_addr();
    arp_packet.set_target_proto_addr(sender_ip);
    arp_packet.set_sender_proto_addr(target_tp);

    // set the target mac address to the sender's mac address
    arp_packet.set_target_hw_addr(arp_packet.get_sender_hw_addr());

    // set operation to a reply
    arp_packet.set_operation(ArpOperation(2));

    let final_packet = EthernetPacket::owned(arp_packet.packet().to_vec()).unwrap();
    Some(final_packet)
}

#[derive(Clone, Copy)]
pub struct EpollRef(pub usize);

impl EpollRef {
    pub fn new(fd: i32, typ: u16) -> Self {
        let mut val = 0u64;
        val |= (typ as u64) << 48;
        val |= (fd as u32 as u64);
        EpollRef(val as usize)
    }

    pub fn unpack(self) -> (i32, u16) {
        let fd = (self.0 & 0xFFFF_FFFF) as u32 as i32;
        let typ = ((self.0 >> 48) & 0xFFFF) as u16;
        (fd, typ)
    }

    pub fn from_u64(val: usize) -> Self {
        EpollRef(val)
    }
}

pub struct Ip4Ctx {
    pub addr: in_addr,
    pub addr_seen: in_addr,
    pub prefix_len: in_addr,
    pub guest_gw: in_addr,
    pub map_host_loopback: in_addr,
    pub map_guest_addr: in_addr,
    pub dns: [in_addr; 4],
    pub dns_match: in_addr,
    pub our_tap_addr: in_addr,

    pub dns_host: in_addr,
    pub addr_out: in_addr,

    pub ifname_out: [u8; 16],

    pub no_copy_routes: bool,
    pub no_copy_addrs: bool,
}

pub fn recv_nonblock(fd: RawFd, buf: &mut [u8], offest: usize) -> nix::Result<usize> {
    loop {
        match recv(fd, &mut buf[offest..], MsgFlags::MSG_DONTWAIT) {
            Ok(n) => return Ok(n),
            Err(e) => return Err(e),
        }
    }
}

pub extern "C" fn exit_handler(signum: libc::c_int) {
    unsafe {
        libc::exit(signum);
    }
}

pub unsafe fn setup_sig_handler(handler: usize, signal: libc::c_int) {
    let mut sa: libc::sigaction = std::mem::zeroed();

    sa.sa_sigaction = handler as usize;
    sa.sa_flags = 0;

    libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
    libc::sigaction(signal, &sa, std::ptr::null_mut());
}
