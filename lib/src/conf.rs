// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Ammar <aerosound161@gmail.com>
use crate::netlink::NetlinkError;
use clap::ValueEnum;
use ipnet::IpNet;
use log::info;
use neli::consts::rtnl::RtAddrFamily;
use pnet::util::MacAddr;
use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::netlink::{nl_get_addr, nl_get_default_gw, nl_get_exit_ifi};
use std::net::{Ipv4Addr, Ipv6Addr};

const GUEST_ADDRESS: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 1]);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::from_octets([169, 254, 2, 2]);

#[derive(Error, Debug)]
pub enum InitConfError {
    #[error("netlink error: {0}")]
    NetlinkError(#[from] NetlinkError),
}
pub struct Conf {
    pub tap_fd: i32,
    pub mode: Mode,
    pub ip4: Ipv4Conf,
    pub ip6: Ipv6Conf,
    pub our_tap_mac: MacAddr,
    pub guest_mac: MacAddr,
}

impl Default for Conf {
    fn default() -> Self {
        Conf {
            tap_fd: 0,
            mode: Mode::Passt,
            ip4: Ipv4Conf::default(),
            ip6: Ipv6Conf::default(),
            our_tap_mac: MacAddr::new(0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55),
            guest_mac: MacAddr::default(),
        }
    }
}

impl Conf {
    pub fn init() -> Result<Self, InitConfError> {
        let ip6conf = ipv6_conf()?;
        let ip4conf = ipv4_conf()?;

        let c = Conf {
            ip6: ip6conf,
            ip4: ip4conf,
            ..Default::default()
        };
        Ok(c)
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

// todo: should we make specific error types for ipv6 and ipv4 ?
pub fn ipv6_conf() -> Result<Ipv6Conf, InitConfError> {
    let ifi = nl_get_exit_ifi(RtAddrFamily::Inet6)?;

    let gatewayv6 = nl_get_default_gw(ifi, RtAddrFamily::Inet6)?;
    let ipscopes = nl_get_addr(ifi, RtAddrFamily::Inet6)?.take().unwrap();

    let mut conf = Ipv6Conf {
        guest_gw: Ipv6Addr::from_octets(gatewayv6.clone().try_into().unwrap()),
        map_host_loopback: Ipv6Addr::from_octets(gatewayv6.try_into().unwrap()),
        ..Default::default()
    };

    if let IpNet::V6(addrv6) = ipscopes.addr {
        conf.addr = addrv6.addr();
        conf.addr_seen = addrv6.addr();
    }
    if let IpNet::V6(addrv6) = ipscopes.link_local_addr {
        conf.our_tap_ll = addrv6.addr();
    }
    info!(
        "initialized ipv6. gateway: {}, addr: {}",
        conf.guest_gw, conf.addr
    );
    Ok(conf)
}

pub fn ipv4_conf() -> Result<Ipv4Conf, InitConfError> {
    let ifi = nl_get_exit_ifi(RtAddrFamily::Inet)?;

    let gatewayv4 = nl_get_default_gw(ifi, RtAddrFamily::Inet)?;
    let ipscopes = nl_get_addr(ifi, RtAddrFamily::Inet)?.take().unwrap();

    let mut conf = Ipv4Conf {
        guest_gw: Ipv4Addr::from_octets(gatewayv4.try_into().unwrap()),
        ..Default::default()
    };
    if let IpNet::V4(addrv4) = ipscopes.addr {
        conf.addr = addrv4.addr();
    }
    // do we need link local setup for v4 ?
    info!(
        "initialized ipv4. gateway: {}, addr: {}",
        conf.guest_gw, conf.addr
    );
    Ok(conf)
}

/*
 * struct ip6_ctx - IPv6 execution context
 * @addr:		IPv6 address assigned to guest, should come from nl_addr_get
 * @addr_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @guest_gw:		IPv6 gateway as seen by the guest
 * @map_host_loopback:	Outbound connections to this address are NATted to the
 *                      host's [::1]
 * @map_guest_addr:	Outbound connections to this address are NATted to the
 *                      guest's assigned address
 * @dns:		DNS addresses for DHCPv6 and NDP
 * @dns_match:		Forward DNS query if sent to this address
 * @our_tap_ll:		Link-local IPv6 address for passt's use on tap, also comes from nl_addr_get
 * @dns_host:		Use this DNS on the host for forwarding
 * @addr_out:		Optional source address for outbound traffic
 * @ifname_out:		Optional interface name to bind outbound sockets to
 * @no_copy_routes:	Don't copy all routes when configuring target namespace
 * @no_copy_addrs:	Don't copy all addresses when configuring namespace
*/

// we need to know where the ip6 context gets created and whats the mac address
pub struct Ipv6Conf {
    pub addr: Ipv6Addr,
    pub addr_seen: Ipv6Addr,
    pub guest_gw: Ipv6Addr,
    pub map_host_loopback: Ipv6Addr,
    pub our_tap_ll: Ipv6Addr,
}

impl Default for Ipv6Conf {
    fn default() -> Self {
        Ipv6Conf {
            addr: Ipv6Addr::UNSPECIFIED,
            addr_seen: Ipv6Addr::UNSPECIFIED,
            guest_gw: Ipv6Addr::UNSPECIFIED,
            map_host_loopback: Ipv6Addr::UNSPECIFIED,
            our_tap_ll: Ipv6Addr::UNSPECIFIED,
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
