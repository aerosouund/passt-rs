use clap::ValueEnum;
use linux_raw_sys::netlink::rtnexthop;
use neli::consts::nl::{NlTypeWrapper, NlmF};
use neli::consts::rtnl::{RtAddrFamily, RtScope, RtTable, Rta, Rtm, Rtn, Rtprot};
use neli::consts::socket::{AddrFamily, NlFamily};
use neli::router::synchronous::NlRouter;
use neli::rtnl::{RtattrBuilder, Rtmsg, RtmsgBuilder};
use neli::types::RtBuffer;
use neli::utils::Groups;
use std::net::IpAddr;

use log::{error, info};
use neli::nl::{NlPayload, Nlmsghdr};
use serde::{Deserialize, Serialize};

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

const GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 1]);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 2]);

// ammar: check what those usually are in passt by default
const V6_GATEWAY_ADDR: Ipv6Addr = Ipv6Addr::from_octets([0; 16]);
const GUEST_V6_ADDRESS: Ipv6Addr = Ipv6Addr::from_octets([0; 16]);

enum InitConfError {}

pub struct Conf {
    pub tap_fd: i32,
    pub nl_socket: NlRouter,
    pub mode: Mode,
    pub ip4: Ipv4Conf,
    pub ip6: Ipv6Conf,
}

impl Conf {
    fn new(nl_sock: NlRouter) -> Self {
        Conf {
            tap_fd: 0,
            nl_socket: nl_sock,
            mode: Mode::Passt,
            ip4: Ipv4Conf::default(),
            ip6: Ipv6Conf::default(),
        }
    }

    fn init() -> Result<Self, std::io::Error> {
        let (nl_socket, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();
        let ifi = nl_get_exit_ifi(&nl_socket, RtAddrFamily::Inet6)?;

        let gatewayv6 = nl_get_default_gw(&nl_socket, ifi, RtAddrFamily::Inet6)?;
        let mut c = Conf::new(nl_socket);
        c.ip6.guest_gw = Ipv6Addr::from_octets(gatewayv6.try_into().unwrap());
        Ok(c)
    }
}

#[allow(unused_assignments)]
pub fn nl_get_exit_ifi(nl_sock: &NlRouter, address_family: RtAddrFamily) -> Result<u32, io::Error> {
    let (mut thisifi, mut defifi, mut anyifi) = (0, 0, 0);
    let mut dest = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // placeholder

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(address_family)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Main)
        .rtm_protocol(Rtprot::Unspec)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unspec)
        .build()
        .unwrap();

    // how much buffer space are we allocating to receive these things ?
    // this api is diabolical. i need to understand it properly
    let recv = nl_sock
        .send::<_, _, NlTypeWrapper, _>(
            Rtm::Getroute,
            NlmF::DUMP | NlmF::REQUEST,
            NlPayload::Payload(rtmsg),
        )
        .unwrap();

    for res in recv {
        let rtm: Nlmsghdr<NlTypeWrapper, Rtmsg> = res.unwrap();
        if let NlTypeWrapper::Rtm(_) = rtm.nl_type() {
            if let Some(payload) = rtm.get_payload() {
                for attr in payload.rtattrs().iter() {
                    match attr.rta_type() {
                        Rta::Oif => {
                            // are attributes just buffers of bytes with a length equal
                            // to the data size of the attribute?
                            // who says its little endian
                            thisifi = u32::from_le_bytes(
                                attr.rta_payload().as_ref()[0..4].try_into().unwrap(),
                            );
                        }
                        Rta::Dst => {
                            // dest is used to detect link local in the c code
                            // dest is an address, we check the first bit of it to see if its a local prefix
                            // we should add a dest variable that will keep track fo the dest we are sent
                            // and it will get overriden by the last attribute. so we should do the check outside of the attribute loop
                            match address_family {
                                RtAddrFamily::Inet6 => {
                                    dest = std::net::IpAddr::V6(Ipv6Addr::from_octets(
                                        attr.rta_payload().as_ref()[0..16].try_into().unwrap(),
                                    ));
                                }
                                RtAddrFamily::Inet => {
                                    dest = std::net::IpAddr::V4(Ipv4Addr::from_octets(
                                        attr.rta_payload().as_ref()[0..4].try_into().unwrap(),
                                    ));
                                }
                                _ => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "invalid address family was passed {:?}",
                                            address_family
                                        ),
                                    ));
                                }
                            }
                        }
                        Rta::Multipath => {
                            // try to find if there is a solution here that doesn't need unsafe
                            let rtnexthop =
                                attr.rta_payload().as_ref() as *const _ as *const rtnexthop;
                            thisifi = unsafe { (*rtnexthop).rtnh_ifindex as u32 }
                        }
                        _ => {
                            // we don't care about that attribute
                            continue;
                        }
                    }
                }
                // we didn't get an oif attribute, or the one we got was the loopback
                if thisifi == 0 || thisifi == 1 {
                    continue;
                }

                match dest {
                    IpAddr::V4(ip4) => {
                        if ip4.is_link_local() {
                            continue;
                        }
                    }
                    IpAddr::V6(ip6) => {
                        if ip6.is_unicast_link_local() {
                            continue;
                        }
                    }
                }

                if *payload.rtm_dst_len() == 0 {
                    defifi = thisifi
                } else {
                    anyifi = thisifi
                }
            }
        }
    }

    if defifi != 0 {
        return Ok(defifi);
    }
    if anyifi != 0 {
        return Ok(anyifi);
    }
    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "there is no interface index with a default route in the main route table",
    ));
}

pub fn nl_get_default_gw(
    nl_sock: &NlRouter,
    iface_idx: u32,
    address_family: RtAddrFamily,
) -> Result<Vec<u8>, io::Error> {
    let oif_attr = RtattrBuilder::default()
        .rta_type(Rta::Oif)
        .rta_payload(iface_idx)
        .build()
        .unwrap();
    let mut attrs = RtBuffer::new();
    attrs.push(oif_attr);

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(address_family)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Main)
        .rtm_protocol(Rtprot::Unspec)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unspec)
        .rtattrs(attrs)
        .build()
        .unwrap();

    let recv = nl_sock
        .send::<_, _, NlTypeWrapper, _>(Rtm::Getroute, NlmF::REQUEST, NlPayload::Payload(rtmsg))
        .unwrap();

    for res in recv {
        let rtm: Nlmsghdr<NlTypeWrapper, Rtmsg> = res.unwrap();
        if let NlTypeWrapper::Rtm(_) = rtm.nl_type() {
            if let Some(payload) = rtm.get_payload() {
                for attr in payload.rtattrs().iter() {
                    match attr.rta_type() {
                        Rta::Gateway => match address_family {
                            RtAddrFamily::Inet => {
                                return Ok(attr.rta_payload().as_ref()[0..4].try_into().unwrap());
                            }
                            RtAddrFamily::Inet6 => {
                                return Ok(attr.rta_payload().as_ref()[0..16].try_into().unwrap());
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "invalid address family was passed {:?}",
                                        address_family
                                    ),
                                ));
                            }
                        },
                        _ => {
                            // an attribute we don't care about
                        }
                    }
                }
            }
        }
    }

    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "found no message with a gateway attribute for interface index",
    ));
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
