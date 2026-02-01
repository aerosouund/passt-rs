use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

const GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 1]);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 2]);

#[derive(Default)]
pub struct Conf {
    pub tap_fd: i32,
    pub mode: Mode,
    pub ip4: Ipv4Conf,
    pub ip6: Ipv6Conf,
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

#[derive(Default)]
pub struct Ipv6Conf {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Passt,
    Pasta,
}
