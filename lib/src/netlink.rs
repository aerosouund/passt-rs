// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Ammar <aerosound161@gmail.com>
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use linux_raw_sys::netlink::rtnexthop;
use neli::consts::nl::{NlTypeWrapper, NlmF};
use neli::consts::rtnl::{Ifa, RtAddrFamily, RtScope, RtTable, Rta, Rtm, Rtn, Rtprot};
use neli::consts::socket::NlFamily;
use neli::router::synchronous::NlRouter;
use neli::rtnl::{Ifaddrmsg, IfaddrmsgBuilder, RtattrBuilder, Rtmsg, RtmsgBuilder};
use neli::types::RtBuffer;
use neli::utils::Groups;
use std::io::Read;
use std::net::IpAddr;
use thiserror::Error;

use neli::nl::{NlPayload, Nlmsghdr};

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct IpScopes {
    pub addr: IpNet,
    pub link_local_addr: IpNet,
}

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("invalid ip length. should be 4 or 16 bytes")]
    InvalidIpLength,
    #[error("failed to get packet attribute")]
    GetAttributeError,
    #[error("invalid address family")]
    InvalidAddressFamily,
    #[error("error reading ip address: {0}")]
    ReadIp(#[from] io::Error),
    #[error("there is no interface index with a default route in the main route table")]
    NoIfaceWithDefaultRoute,
    #[error("found no message with a gateway attribute for interface index")]
    NoGatewayAttribute,
}

/// get the interface that has a route with the shortest possible prefix (as close as possible to zero)
/// we will send a message to dump all routes and we will go over them to get the interface index we want.
#[allow(unused_assignments)]
pub fn nl_get_exit_ifi(address_family: RtAddrFamily) -> Result<u32, NetlinkError> {
    let (nl_sock, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();
    let (mut thisifi, mut defifi, mut anyifi) = (0, 0, 0);

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(address_family)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Main)
        .rtm_protocol(Rtprot::Unspec)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unicast)
        .build()
        .unwrap();

    // ammar: how much buffer space are we allocating to receive these things ?
    // ammar: this api is diabolical. i need to understand it properly
    let recv = nl_sock
        .send::<_, _, NlTypeWrapper, _>(
            Rtm::Getroute,
            NlmF::DUMP | NlmF::REQUEST,
            NlPayload::Payload(rtmsg),
        )
        .unwrap();

    for res in recv {
        let rtm: Nlmsghdr<NlTypeWrapper, Rtmsg> = res.unwrap();
        let mut dest = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // placeholder

        if let NlTypeWrapper::Rtm(_) = rtm.nl_type()
            && let Some(payload) = rtm.get_payload()
        {
            // iterate over each route message attributes
            for attr in payload.rtattrs().iter() {
                match attr.rta_type() {
                    // if the attribute is an Oif (index of an interface), we will parse it
                    // because eventually we wanna return an interface index
                    Rta::Oif => {
                        thisifi = u32::from_le_bytes(
                            attr.rta_payload().as_ref()[0..4].try_into().unwrap(),
                        );
                    }
                    // a Dst attribute is basically the destination address of that route, we
                    // are trying to search for the default, but we will return this is we didn't
                    // find a default. for example:
                    // 10.0.0.0/8 via 10.0.0.1 dev eth1, 10.0.0.0/8 is the Dst
                    Rta::Dst => {
                        // todo: shortest prefix matching is still missing here
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
                                return Err(NetlinkError::InvalidAddressFamily);
                            }
                        }
                    }
                    // a Multipath attribute is when there are multiple interfaces for one route
                    // and the kernel is supposed to load balance between them. for example:
                    // default via 192.168.1.1 dev eth0 weight 1
                    //         via 192.168.1.2 dev eth1 weight 1
                    Rta::Multipath => {
                        // todo: try to find if there is a solution here that doesn't need unsafe
                        let rtnexthop = attr.rta_payload().as_ref() as *const _ as *const rtnexthop;
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

            // if the dest_len is zero, then immediately thats the default gateway route
            // we want to get the index of the interface of that route
            if *payload.rtm_dst_len() == 0 {
                defifi = thisifi
            } else {
                anyifi = thisifi
            }
        }
    }

    if defifi != 0 {
        return Ok(defifi);
    }
    if anyifi != 0 {
        return Ok(anyifi);
    }
    Err(NetlinkError::NoIfaceWithDefaultRoute)
}

// given an interface index, get all the addresses configured on it and return the one with the
// highest prefix (a /32).
pub fn nl_get_addr(
    iface_idx: u32,
    address_family: RtAddrFamily,
) -> Result<Option<IpScopes>, NetlinkError> {
    let (nl_sock, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();

    let mut max_prefix = 0;
    let mut ipscopes = {
        match address_family {
            RtAddrFamily::Inet => IpScopes {
                addr: IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0)),
                link_local_addr: IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0)),
            },
            RtAddrFamily::Inet6 => IpScopes {
                addr: IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 0)),
                link_local_addr: IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 0)),
            },
            _ => {
                return Err(NetlinkError::InvalidAddressFamily);
            }
        }
    };

    let ifmsg = IfaddrmsgBuilder::default()
        .ifa_family(address_family)
        .ifa_prefixlen(0)
        .ifa_scope(RtScope::Universe)
        .ifa_index(iface_idx)
        .build()
        .unwrap();

    let recv = nl_sock
        .send::<_, _, NlTypeWrapper, _>(Rtm::Getaddr, NlmF::DUMP, NlPayload::Payload(ifmsg))
        .unwrap();

    for res in recv {
        let msg = res.unwrap();
        if let NlPayload::<_, Ifaddrmsg>::Payload(p) = msg.nl_payload() {
            // todo: there was another condition related to a flag ?
            if *p.ifa_index() != iface_idx {
                continue;
            }

            // small prefix, skip it
            let current_prefix_length = *p.ifa_prefixlen();
            if current_prefix_length < max_prefix {
                continue;
            }

            let scope = p.ifa_scope();
            let handle = p.rtattrs().get_attr_handle();
            let addr = {
                // todo: this function name is pretty annoying. i should search for a different way of doing this
                if let Ok(mut ip_bytes) =
                    handle.get_attr_payload_as_with_len_borrowed::<&[u8]>(Ifa::Address)
                {
                    if ip_bytes.len() == 4 {
                        let mut bytes = [0u8; 4];
                        ip_bytes
                            .read_exact(&mut bytes)
                            .map_err(NetlinkError::ReadIp)?;
                        let a = Ipv4Addr::from(u32::from_ne_bytes(bytes).to_be());

                        IpNet::from(Ipv4Net::new(a, current_prefix_length).unwrap())
                    } else if ip_bytes.len() == 16 {
                        let mut bytes = [0u8; 16];
                        ip_bytes
                            .read_exact(&mut bytes)
                            .map_err(NetlinkError::ReadIp)?;
                        let a = Ipv6Addr::from(u128::from_ne_bytes(bytes).to_be());

                        IpNet::from(Ipv6Net::new(a, current_prefix_length).unwrap())
                    } else {
                        return Err(NetlinkError::InvalidIpLength);
                    }
                } else {
                    return Err(NetlinkError::GetAttributeError);
                }
            };
            // move this address to return address because its the most specific one we saw up until now
            match scope {
                RtScope::Link => {
                    ipscopes.link_local_addr = addr;
                }
                RtScope::Universe | RtScope::Site => {
                    ipscopes.addr = addr;
                }
                _ => {}
            };
            max_prefix = current_prefix_length;
        }
    }
    Ok(Some(ipscopes))
}

// given an interface index, get the address with the shortest prefix (default)
pub fn nl_get_default_gw(
    iface_idx: u32,
    address_family: RtAddrFamily,
) -> Result<Vec<u8>, NetlinkError> {
    let (nl_sock, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty()).unwrap();

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
        .rtm_type(Rtn::Unicast)
        .rtattrs(attrs)
        .build()
        .unwrap();

    let recv = nl_sock
        .send::<_, _, NlTypeWrapper, _>(Rtm::Getroute, NlmF::DUMP, NlPayload::Payload(rtmsg))
        .unwrap();

    for res in recv {
        let rtm: &Nlmsghdr<NlTypeWrapper, Rtmsg> = res.as_ref().unwrap();
        if let NlTypeWrapper::Rtm(_) = rtm.nl_type()
            && let Some(payload) = rtm.get_payload()
        {
            // if this route has a non_zero dest_len, it's immediately not the default
            if *payload.rtm_dst_len() != 0 {
                continue;
            }

            for attr in payload.rtattrs().iter() {
                match attr.rta_type() {
                    // the gateway attribute is the next hop for some route
                    // since we already excluded the routes that don't have a zero dest len
                    // so if we are here then this means this is a default via x.x.x.x route
                    // the x's bit is the gateway and is what we are interested in
                    Rta::Gateway => match address_family {
                        RtAddrFamily::Inet => {
                            return Ok(attr.rta_payload().as_ref()[0..4].into());
                        }
                        RtAddrFamily::Inet6 => {
                            return Ok(attr.rta_payload().as_ref()[0..16].into());
                        }
                        _ => {
                            return Err(NetlinkError::InvalidAddressFamily);
                        }
                    },
                    Rta::Multipath => {
                        // understanding neli is no longer a joke here. this shit feels like magic in a way i find annoying
                        let a = attr.get_attr_handle::<Rta>().unwrap();
                        let inner = a.get_attrs();
                        // ammar: finish this snippet to make it extract nested gateway attributes and
                        // get their payloads appropriately
                        for inner_attr in inner {
                            if let Rta::Gateway = inner_attr.rta_type() {
                                let _inner_payload = inner_attr.rta_payload();
                            }
                        }
                    }
                    _ => {
                        // an attribute we don't care about
                    }
                }
            }
        }
    }

    Err(NetlinkError::NoGatewayAttribute)
}
