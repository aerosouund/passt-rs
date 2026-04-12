use clap::ValueEnum;
use neli::FromBytes;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteMessageBuffer, RouteScope,
};

use log::{error, info};
use neli::nl::Nlmsghdr;
use serde::{Deserialize, Serialize};

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, Parseable};
use nix::sys::socket::{SockFlag, SockProtocol, bind, socket};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 1]);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 2]);

// ammar: check what those usually are in passt by default
const V6_GATEWAY_ADDR: Ipv6Addr = Ipv6Addr::from_octets([0; 16]);
const GUEST_V6_ADDRESS: Ipv6Addr = Ipv6Addr::from_octets([0; 16]);

pub struct Conf {
    pub tap_fd: i32,
    pub nl_socket: OwnedFd, // ammar: this is not ideal. we need to either initialize the netlink socket somewhere else or have this be an i32
    pub mode: Mode,
    pub ip4: Ipv4Conf,
    pub ip6: Ipv6Conf,
}

impl Default for Conf {
    fn default() -> Self {
        Conf {
            tap_fd: 0,
            nl_socket: unsafe { OwnedFd::from_raw_fd(0) },
            mode: Mode::Passt,
            ip4: Ipv4Conf::default(),
            ip6: Ipv6Conf::default(),
        }
    }
}

impl Conf {
    fn init() -> Result<Self, std::io::Error> {
        let nl_socket = init_netlink_socket()?;
        let mut c = Conf::default();
        let gatewayv6 = nl_get_default_gw_v6(&nl_socket, 0)?; // where should the interface index come from ?

        c.nl_socket = nl_socket;
        Ok(c)
    }
}

pub fn init_netlink_socket() -> Result<OwnedFd, std::io::Error> {
    let fd = socket(
        nix::sys::socket::AddressFamily::Netlink,
        nix::sys::socket::SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    // then bind
    // how to build a netlink socket address ?
    // bind(fd, addr)

    Ok(fd)
}

#[allow(unused_assignments)]
pub fn nl_get_exit_ifi_v6(nl_sock: &OwnedFd) -> Result<u32, io::Error> {
    let mut nl_hdr = NetlinkHeader::default();
    let mut route_msg = RouteMessage::default();
    let attr: Vec<RouteAttribute> = Vec::new();

    let (mut thisifi, mut defifi, mut anyifi) = (0, 0, 0);

    // set the dump flag on the header NLM_F_DUMP
    nl_hdr.flags |= netlink_packet_core::NLM_F_DUMP;
    route_msg.attributes = attr;
    route_msg.header.table = RouteHeader::RT_TABLE_MAIN;
    route_msg.header.scope = RouteScope::Universe;
    route_msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;

    let nl_msg = NetlinkMessage::new(
        nl_hdr,
        netlink_packet_core::NetlinkPayload::InnerMessage(route_msg),
    );

    let n = unsafe {
        libc::send(
            nl_sock.as_raw_fd(),
            &nl_msg as *const _ as *mut std::ffi::c_void,
            std::mem::size_of_val(&nl_msg),
            0,
        )
    };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut recv_buf: Vec<u8> = vec![0u8; 65536];

    loop {
        // if this is a non blocking socket then we would get e would block if messages ran out
        let n = unsafe {
            libc::recv(
                nl_sock.as_raw_fd(),
                recv_buf.as_mut_ptr() as *mut std::ffi::c_void,
                std::mem::size_of_val(&recv_buf),
                0,
            )
        };
        if n == -1 {
            return Err(io::Error::last_os_error());
        }

        let received = recv_buf.as_slice();
        let mut offset = 0;
        let hdr_size = std::mem::size_of::<libc::nlmsghdr>();

        let mut cursor = std::io::Cursor::new(received);
        while offset + hdr_size < received.len() {
            let hdr = unsafe {
                std::ptr::read_unaligned(received.as_ptr().add(offset) as *const libc::nlmsghdr)
            };
            // wtf is this garbage man this nli packet forces me to get also a payload ???
            let nli_hdr = Nlmsghdr::from_bytes(&mut cursor);
            offset += hdr_size;

            let msg_len = hdr.nlmsg_len as usize;

            if offset + msg_len > received.len() {
                // check if we have up to msg_len bytes in the buffer or less (truncate)
            }
            // switch on the msg header type and check if we can convert this libc type into a safe type

            offset += msg_len;
        }

        let nl_msghdr = recv_buf.as_mut_ptr() as *mut libc::nlmsghdr;

        /*
        - for (whats remaining is less than the length of an ethernet header)
        - read a header
        - read the length if we have up to that length available in the buffer still
        - if we don't then we need to receive more bytes into a new buffer and we need to store the partial buffer somewhere
        - thats a packet
        - advance offset by header+len
         */
        let msg_size = unsafe { std::ptr::read_unaligned(&(*nl_msghdr).nlmsg_len) };
        // create a message starting from 0 till header offset up until header length

        let buf: RouteMessageBuffer<&[u8; 10]> =
            RouteMessageBuffer::new(recv_buf.as_array().unwrap());

        // i need to be able to continue on error but i can't error on the closure
        let route_msg: RouteMessage;

        if let Ok(rtm) = RouteMessage::parse(&buf) {
            route_msg = rtm;
        } else {
            // find a way to still have access to the error
            error!("failed to parse the message as a netlink route message",);
            continue;
        }

        for attr in route_msg.attributes.to_owned() {
            match attr {
                RouteAttribute::Oif(ifi) => {
                    thisifi = ifi;
                }
                RouteAttribute::Destination(addr) => {}
                RouteAttribute::MultiPath(next_hops) => {}
                _ => {}
            }
        }

        // we didn't get an oif attribute, or the one we got was the loopback
        if thisifi == 0 || thisifi == 1 {
            continue;
        }

        if route_msg.header.destination_prefix_length == 0 {
            // we wanna get the first interface index with ba default route
            // the c code did some logging around this but for simplicity we just wanna get this default first interface
            defifi = thisifi
        } else {
            // in the c code we try to set two variables to keep track of the different types of route prefixes the interface we are
            // processing has. the defifi and anyifi
            // we will in the end return defifi because its more general
            anyifi = thisifi
        }
        // in the c code how do we break out of the message processing loop ?
    }
}

pub fn nl_get_default_gw_v6(nl_sock: &OwnedFd, iface_idx: u32) -> Result<Ipv6Addr, io::Error> {
    let nl_hdr = NetlinkHeader::default();
    let mut route_msg = RouteMessage::default();
    let mut attr: Vec<RouteAttribute> = Vec::new();
    attr.push(RouteAttribute::Oif(iface_idx));

    route_msg.attributes = attr;
    route_msg.header.table = RouteHeader::RT_TABLE_MAIN;
    route_msg.header.scope = RouteScope::Universe;
    route_msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;

    let nl_msg = NetlinkMessage::new(
        nl_hdr,
        netlink_packet_core::NetlinkPayload::InnerMessage(route_msg),
    );

    let n = unsafe {
        libc::send(
            nl_sock.as_raw_fd(),
            &nl_msg as *const _ as *mut std::ffi::c_void,
            std::mem::size_of_val(&nl_msg),
            0,
        )
    };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    // receive from the socket the message type you are expecting, which is RTM_NEWROUTE
    loop {
        let rt_msg_size = std::mem::size_of::<RouteMessage>();
        let mut recv_buf: Vec<u8> = vec![0u8; rt_msg_size];
        let n = unsafe {
            libc::recv(
                nl_sock.as_raw_fd(),
                recv_buf.as_mut_ptr() as *mut std::ffi::c_void,
                std::mem::size_of_val(&recv_buf),
                0,
            )
        };
        if n == -1 {
            return Err(io::Error::last_os_error());
        }

        let buf: RouteMessageBuffer<&[u8; 10]> =
            RouteMessageBuffer::new(recv_buf.as_array().unwrap());

        if let Ok(rtm) = RouteMessage::parse(&buf) {
            for attr in rtm.attributes.to_owned() {
                match attr {
                    RouteAttribute::Gateway(addr) => {
                        if let RouteAddress::Inet6(a) = addr {
                            return Ok(a);
                        } else {
                            info!("gateway address wasn't ipv6");
                            continue;
                        }
                    }
                    _ => {}
                }
            }
        } else {
            // find a way to still have access to the error
            error!("failed to parse the message as a netlink route message",);
            continue;
        }
    }
}

pub struct Ipv4Conf {
    pub prefix_len: u8,
    pub guest_gw: Ipv4Addr,
    pub our_tap_addr: Ipv4Addr,
    pub addr: Ipv4Addr,
}

impl Default for Ipv4Conf {
    fn default() -> Self {
        Ipv4Conf {
            prefix_len: 0,
            guest_gw: GATEWAY_IP,
            our_tap_addr: GATEWAY_IP,
            addr: GUEST_ADDRESS,
        }
    }
}

/*
* struct ip6_ctx {
   /* PIF_TAP addresses */
   struct in6_addr addr;
   struct in6_addr addr_seen;
   struct in6_addr addr_ll_seen;
   struct in6_addr guest_gw;
   struct in6_addr map_host_loopback;
   struct in6_addr map_guest_addr;
   struct in6_addr dns[MAXNS];
   struct in6_addr dns_match;
   struct in6_addr our_tap_ll;

   /* PIF_HOST addresses */
   struct in6_addr dns_host;
   struct in6_addr addr_out;

   char ifname_out[IFNAMSIZ];

   bool no_copy_routes;
   bool no_copy_addrs;
};
*/

// we need to know where the ip6 context gets created and whats the mac address
pub struct Ipv6Conf {
    pub addr: Ipv6Addr,
    pub addr_seen: Ipv6Addr,
    pub addr_ll_seen: Ipv6Addr,
    pub guest_gw: Ipv6Addr,
    pub map_host_loopback: Ipv6Addr,
    pub map_guest_addr: Ipv6Addr,
    pub our_tap_ll: Ipv6Addr,
}

impl Default for Ipv6Conf {
    fn default() -> Self {
        Ipv6Conf {
            addr: V6_GATEWAY_ADDR,
            addr_seen: V6_GATEWAY_ADDR,
            addr_ll_seen: V6_GATEWAY_ADDR,
            guest_gw: V6_GATEWAY_ADDR,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Passt,
    Pasta,
}
