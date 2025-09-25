use libc::in_addr;
use mio::net::UnixStream;
use pnet::packet::ethernet::EtherTypes::Arp;
use pnet::packet::ethernet::EthernetPacket;

pub const MAX_FRAME: usize = 65535 + 4;

#[derive(Default)]
pub struct Context {
    pub debug: i32,
    pub trace: i32,
    pub stream: Option<UnixStream>, // <- optional
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

pub fn handle_packets<'a>(packets: Vec<EthernetPacket<'a>>) {
    for p in packets.iter() {
        if p.get_ethertype() == Arp {
            // handle arp
            handle_arp(p);
            continue;
        };
    }
}

pub fn handle_arp<'a>(p: &EthernetPacket<'a>) {}
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
