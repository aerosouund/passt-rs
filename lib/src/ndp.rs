// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Ammar <aerosound161@gmail.com>
use std::net::Ipv6Addr;

use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6::ndp::{
    MutableNeighborAdvertPacket, MutableRouterAdvertPacket, NdpOption, NdpOptionTypes,
};
use pnet::packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::{MutablePacket, Packet};

use crate::conf::Conf;
use crate::icmp::IcmpError;
use crate::utils::send_ether;

pub(crate) fn neighbour_advert(
    conf: &Conf,
    dest: Ipv6Addr,
    addr: Ipv6Addr,
) -> Result<(), IcmpError> {
    // 8 is an arbitrary number for the option length. we need to verify that
    let mut na_buf = vec![0u8; MutableNeighborAdvertPacket::minimum_packet_size() + 8];
    let mut neighbor_adv = MutableNeighborAdvertPacket::new(&mut na_buf).unwrap();

    neighbor_adv.set_target_addr(addr);
    let l2_opt = NdpOption {
        option_type: NdpOptionTypes::TargetLLAddr,
        length: 1,
        data: conf.our_tap_mac.octets().to_vec(),
    };
    neighbor_adv.set_options(&[l2_opt]);
    neighbor_adv.set_flags(0b111); // R=1, S=1, O=1

    let mut v6_packet_vec =
        vec![0u8; MutableIpv6Packet::minimum_packet_size() + neighbor_adv.packet().len()];

    let mut v6reply = MutableIpv6Packet::new(&mut v6_packet_vec).unwrap();
    v6reply.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6reply.set_payload_length(neighbor_adv.packet().len() as u16);
    v6reply.set_payload(neighbor_adv.packet());
    v6reply.set_source(conf.ip6.our_tap_ll);
    v6reply.set_destination(dest);

    send_ether(conf, EtherTypes::Ipv6, v6reply.packet()).map_err(IcmpError::Tap)
}

pub(crate) fn router_advert(conf: &Conf, dest: Ipv6Addr) -> Result<(), IcmpError> {
    let mut prefix_opt_data = Vec::with_capacity(32);
    // ammar: verify if we need this
    let mut addr_bytes = conf.ip6.addr.octets();
    addr_bytes[8..].fill(0);

    prefix_opt_data.push(64);
    prefix_opt_data.push(0xC0);
    prefix_opt_data.extend_from_slice(&u32::MAX.to_be_bytes());
    prefix_opt_data.extend_from_slice(&u32::MAX.to_be_bytes());
    prefix_opt_data.extend_from_slice(&0u32.to_be_bytes());
    prefix_opt_data.extend_from_slice(&addr_bytes);

    // build the options vector
    let options = [
        NdpOption {
            option_type: NdpOptionTypes::PrefixInformation,
            length: 4,
            data: prefix_opt_data,
        },
        NdpOption {
            option_type: NdpOptionTypes::SourceLLAddr,
            length: 1,
            data: conf.our_tap_mac.octets().to_vec(),
        },
    ];
    // 32 and eight are two constants we are unsure of, they are the theoretical size of the
    // prefix opt (32) and the source link local opt (8). we need to verify them though
    let mut buf = vec![0u8; MutableRouterAdvertPacket::minimum_packet_size() + 32 + 8];
    let mut router_adv = MutableRouterAdvertPacket::new(&mut buf).unwrap();
    router_adv.set_hop_limit(255);
    router_adv.set_options(&options);

    let mut v6_packet_vec =
        vec![0u8; MutableIpv6Packet::minimum_packet_size() + router_adv.packet().len()];

    // first, we build an ipv6 view on the router advertisement packet to set source, destination
    // and other common ipv6 information
    let mut v6reply = MutableIpv6Packet::new(&mut v6_packet_vec).unwrap();
    v6reply.set_next_header(IpNextHeaderProtocols::Icmpv6);
    v6reply.set_payload_length(router_adv.packet().len() as u16);
    v6reply.set_payload(router_adv.packet());
    v6reply.set_source(conf.ip6.our_tap_ll);
    v6reply.set_destination(dest);

    // we need to then build an icmpv6 view so we can compute and set the checksum
    let mut crazy_icmp = MutableIcmpv6Packet::new(v6reply.packet_mut()).unwrap();

    let cs = pnet::util::ipv6_checksum(
        crazy_icmp.packet(),
        1,
        &[],
        &conf.ip6.our_tap_ll,
        &dest,
        IpNextHeaderProtocols::Icmpv6,
    );
    crazy_icmp.set_checksum(cs);
    send_ether(conf, EtherTypes::Ipv6, crazy_icmp.packet()).map_err(IcmpError::Tap)
}
