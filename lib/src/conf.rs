use clap::ValueEnum;
use nix::sys::socket::NetlinkAddr;
use serde::{Deserialize, Serialize};

use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_route::NetlinkMessage;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{FromRawFd, OwnedFd};

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

    Ok(fd)
}

pub fn nl_get_default_gw(nl_sock: &OwnedFd) {
    let nl_msg = netlink_packet_core::N
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
