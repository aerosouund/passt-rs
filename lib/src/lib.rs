// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Ammar <aerosound161@gmail.com>
use icmp::handle_icmp6_packet;
use log::error;
use mio::Registry;
use mio::net::UnixStream;
use muxer::ConnEnum;
use muxer::StreamConnCtx;
use pnet::packet::Packet;
use pnet::packet::arp::ArpOperation;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::io::{Read, Write};
use thiserror::Error;
use udp::DhcpError;
use udp::dhcp;

use crate::conf::Conf;
use crate::icmp::IcmpError;

pub mod conf;
pub mod flow;
pub mod fwd;
pub mod icmp;
pub mod muxer;
pub mod ndp;
pub mod netlink;
pub mod udp;
pub mod utils;

pub const MAX_FRAME: usize = 65535 + 4;
const MIN_FRAME: usize = MutableEthernetPacket::minimum_packet_size();

#[derive(Debug, Error)]
pub enum HandlePacketError {
    #[error("icmp error: {0}")]
    Icmp(#[from] IcmpError),
    #[error("dhcp error: {0}")]
    Dhcp(#[from] DhcpError),
    #[error("malformed packet")]
    MalformedPacket,
}

#[derive(Debug, thiserror::Error)]
pub enum TapError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse packet size: {0}")]
    PacketSizeParse(#[from] std::array::TryFromSliceError),
    #[error("invalid size: {0}, max ({MAX_FRAME}), min ({MIN_FRAME})")]
    InvalidSize(usize),
    #[error("malformed ethernet frame")]
    MalformedFrame,
    #[error("incomplete frame, {0} bytes remaining")]
    IncompleteFrame(usize),
}

#[allow(non_upper_case_globals)]
pub fn handle_packets(
    conf: &Conf,
    reg: &Registry,
    stream: &mut UnixStream,
    packets: &mut Vec<EthernetPacket<'static>>,
    conn_map: &mut HashMap<mio::Token, ConnEnum>,
) -> Result<(), HandlePacketError> {
    for p in packets.drain(..) {
        match p.get_ethertype() {
            EtherTypes::Arp => {
                if let Some(final_packet) = handle_arp_packet(&mut p.packet().to_vec()) {
                    let _ = stream
                        .write(final_packet.packet())
                        .map_err(|e| error!("{}", e));
                };
            }

            EtherTypes::Ipv6 => {
                if let Some(v6packet) = Ipv6Packet::owned(p.payload().to_vec())
                    && let Err(e) = tap_handle_v6(conf, v6packet, reg, conn_map)
                {
                    error!("{}", e);
                }
            }

            EtherTypes::Ipv4 => {
                if let Some(v4packet) = Ipv4Packet::owned(p.payload().to_vec())
                    && let Err(e) = tap_handle_v4(conf, v4packet, reg, conn_map)
                {
                    error!("{}", e);
                }
            }

            _ => {}
        }
    }
    Ok(())
}

// todo: think of a better structure to sequence how we handle icmp and its
// child protocols
fn tap_handle_v6(
    conf: &Conf,
    v6packet: Ipv6Packet<'static>,
    // todo: is there any scenario will we need the registry and the connection map?
    _reg: &Registry,
    _conn_map: &mut HashMap<mio::Token, ConnEnum>,
) -> Result<(), HandlePacketError> {
    match v6packet.get_next_header() {
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmp6_packet(conf, v6packet)?;
        }
        // this is here to disable the lint
        IpNextHeaderProtocols::Ax25 => {}
        _ => {}
    }
    Ok(())
}

fn tap_handle_v4(
    conf: &Conf,
    v4packet: Ipv4Packet<'static>,
    reg: &Registry,
    conn_map: &mut HashMap<mio::Token, ConnEnum>,
) -> Result<(), HandlePacketError> {
    match v4packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Icmp => {
            // handle when we return no new connections
            if let Some((token, conn)) =
                icmp::handle_icmp4_packet(reg, v4packet).map_err(HandlePacketError::from)?
            {
                conn_map.insert(token, conn);
            };
        }
        IpNextHeaderProtocols::Udp => {
            let udp_packet = UdpPacket::new(v4packet.payload()).unwrap();
            // dhcp ? but again, we could send whatever on port 67 but hey
            if udp_packet.get_destination() == 67 {
                // todo: handle this result
                let _ = dhcp(conf, v4packet);
            }
        }
        IpNextHeaderProtocols::Tcp => {}
        _ => {}
    }
    Ok(())
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
pub struct EthernetResult {
    pub packets: Vec<EthernetPacket<'static>>,
    pub observed_mac: MacAddr,
}

// this function needs to be able to control mac address
pub fn handle_tap_ethernet(ctx: &mut StreamConnCtx) -> Result<EthernetResult, TapError> {
    let mut buf = [0u8; MAX_FRAME];
    let mut v4_packets: Vec<EthernetPacket<'static>> = Vec::new();
    let mut offset = 0;
    if !ctx.partial_frame.is_empty() {
        buf.clone_from_slice(ctx.partial_frame());
        offset += ctx.partial_frame.len();
    }
    let mut n = ctx.stream.read(&mut buf[offset..])?;
    let mut observed_mac = MacAddr::default();

    while n > 4 {
        let l2len = u32::from_be_bytes(
            buf[offset..offset + 4]
                .try_into()
                .map_err(TapError::PacketSizeParse)?,
        ) as usize;

        // todo: use a cursor here
        if l2len > MAX_FRAME {
            return Err(TapError::InvalidSize(l2len));
        }
        offset += 4;
        n -= 4;
        if let Some(packet) = EthernetPacket::owned(buf[offset..offset + l2len].to_vec()) {
            let src = packet.get_source();
            if observed_mac != src {
                observed_mac = src
            }

            v4_packets.push(packet);
        };

        offset += l2len;
        n -= l2len;
        if l2len > buf[offset..].len() {
            ctx.partial_frame.clone_from_slice(&buf[offset..]);
        }
    }
    Ok(EthernetResult {
        packets: v4_packets,
        observed_mac,
    })
}
