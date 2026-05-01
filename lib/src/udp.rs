// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Ammar <aerosound161@gmail.com>
use crate::TapError;
use crate::conf::Conf;
use crate::utils::send_ether;
use dhcproto::v4::{Decoder, DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Encodable, Encoder};
use ipnet::Ipv4Net;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet, ipv4::MutableIpv4Packet, udp::MutableUdpPacket};
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UdpError {
    #[error("sys error: {0}")]
    SysError(i32),
    #[error("tap error: {0}")]
    Tap(#[from] TapError),
}

pub fn handle_udp() -> Result<(), UdpError> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum DhcpError {
    #[error("invalid packet")]
    InvalidPacket,
    #[error("invalid packet type")]
    InvalidType,
}

// todo: add results and errors and handle them
pub fn tap_udp4_sent(
    conf: &Conf,
    src: Ipv4Addr,
    srcport: i32,
    dest: Ipv4Addr,
    destport: i32,
    msg: Vec<u8>,
) -> Result<(), UdpError> {
    // packet initialization, then buffer appending stuff
    let mut udp_packet = MutableUdpPacket::owned(msg).unwrap();
    udp_packet.set_source(srcport.to_be() as u16);
    udp_packet.set_destination(destport.to_be() as u16);
    // udp_packet.set_checksum(val); // ammar: we need to compute packet checksums

    // ammar: need to make sure if actually wrapping the udp packet in an ipv4 packet is needed here
    // does calling payload return the full packet or just the payload ? according to chatgpt its the whole
    // packet and in a format the os can handle but i am honestly not convinced
    let mut ip_packet = MutableIpv4Packet::new(udp_packet.payload_mut()).unwrap();
    ip_packet.set_source(src);
    ip_packet.set_destination(dest);

    send_ether(conf, EtherTypes::Ipv4, ip_packet.payload()).map_err(UdpError::Tap)
}

pub(crate) fn dhcp(conf: &Conf, udp_pkt: &UdpPacket) -> Result<(), DhcpError> {
    let mut dhcp_msg = match Message::decode(&mut Decoder::new(udp_pkt.payload())) {
        Ok(msg) => msg,
        Err(_) => {
            return Err(DhcpError::InvalidPacket);
        }
    };

    // copy the options outside then set them back to the message at the end (zero copy my ass i guess)
    let mut opts = dhcp_msg.opts_mut().clone();
    // i wish i can get rid of this clone while reading the message type. i don't need to hold a reference to opts
    let msgtype = opts
        .get(dhcproto::v4::OptionCode::MessageType)
        .unwrap()
        .clone();

    if let DhcpOption::MessageType(msg_type) = msgtype {
        let response_type = match msg_type {
            MessageType::Discover => {
                if opts.contains(OptionCode::RapidCommit) {
                    MessageType::Offer
                } else {
                    MessageType::Ack
                }
            }
            MessageType::Request => MessageType::Ack,
            _ => {
                return Err(DhcpError::InvalidType);
            }
        };
        opts.insert(DhcpOption::MessageType(response_type));
    };
    let mask = (!0u32 << (32 - conf.ip4.prefix_len as u32)).to_be();

    dhcp_msg.set_yiaddr(conf.ip4.addr);
    opts.insert(DhcpOption::SubnetMask(Ipv4Addr::BROADCAST));
    opts.insert(DhcpOption::Router(vec![conf.ip4.guest_gw]));
    opts.insert(DhcpOption::ServerIdentifier(conf.ip4.our_tap_addr));

    if conf.ip4.guest_gw.to_bits() & mask != conf.ip4.addr.to_bits() & mask {
        opts.insert(DhcpOption::ClasslessStaticRoute(vec![(
            Ipv4Net::new(conf.ip4.guest_gw, 32).unwrap(),
            conf.ip4.guest_gw,
        )]));
    }

    // eventually
    dhcp_msg.set_opts(opts);
    let mut msg_buf = Vec::new();
    let mut enc = Encoder::new(&mut msg_buf);
    dhcp_msg.encode(&mut enc).unwrap();

    // do we build a new packet or use the existing one ?
    tap_udp4_sent(conf, conf.ip4.our_tap_addr, 67, conf.ip4.addr, 68, msg_buf).unwrap();
    Ok(())
}
