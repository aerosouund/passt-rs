use clap::ValueEnum;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

const GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 1]);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 2]);
const TAP_MAC: [u8; 6] = [0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55];
#[derive(Default)]
pub struct Conf {
    pub tap_fd: i32,
    pub nl_socket: i32,
    pub mode: Mode,
    pub ip4: Ipv4Conf,
    pub ip6: Ipv6Conf,
    pub tap_mac: [u8; 6],
}

impl Conf {
    fn init() -> Self {
        // change this later
        let mut conf = Conf::default();
        conf.tap_mac = TAP_MAC;
        conf
    }
}

fn init_netlink_socket() -> Result<i32, io::Error> {
    Ok(0)
}

/*
* struct ip4_ctx {
* 	ip4->addr_seen = ip4->addr = ;
    ip4->our_tap_addr = ip4->guest_gw = ;

   /* PIF_TAP addresses */
   struct in_addr addr; IP4_LL_GUEST_ADDR
   struct in_addr addr_seen; IP4_LL_GUEST_ADDR
   int prefix_len;
   struct in_addr guest_gw; IP4_LL_GUEST_GW
   struct in_addr map_host_loopback;
   struct in_addr map_guest_addr;
   struct in_addr dns[MAXNS + 1];
   struct in_addr dns_match;
   struct in_addr our_tap_addr; IP4_LL_GUEST_GW

   /* PIF_HOST addresses */
   struct in_addr dns_host;
   struct in_addr addr_out;

   char ifname_out[IFNAMSIZ];

   bool no_copy_routes;
   bool no_copy_addrs;
};
*/

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

// we need to know where the ip6 context gets created and whats the mac address
pub struct Ipv6Conf {
    pub addr: Ipv6Addr,
}

impl Default for Ipv6Conf {
    fn default() -> Self {
        Ipv6Conf {
            // fill later with real addr
            addr: Ipv6Addr::from_octets([0; 16]),
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
