use dhcproto::v4::{Decoder, DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Encodable, Encoder};
use ipnet::Ipv4Net;
use log::error;
use mio::Registry;
use mio::net::UnixStream;
use muxer::StreamConnCtx;
use pnet::packet::Packet;
use pnet::packet::arp::ArpOperation;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

use crate::conf::Conf;
use crate::icmp::IcmpError;
use crate::muxer::ConnEnum;
use crate::udp::tap_udp4_sent;

pub mod conf;
pub mod flow;
pub mod fwd;
pub mod icmp;
pub mod muxer;
pub mod udp;

pub const MAX_FRAME: usize = 65535 + 4;

#[derive(Debug)]
pub struct HandlePacketError(pub String);

impl std::fmt::Display for HandlePacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HandlePacketError {}

impl From<IcmpError> for HandlePacketError {
    fn from(value: IcmpError) -> Self {
        HandlePacketError(value.to_string())
    }
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

            // guess we will have to work on this ahead of schedule
            EtherTypes::Ipv6 => {
                if let Some(v6packet) = Ipv6Packet::owned(p.payload().to_vec()) {
                    match v6packet.get_next_header() {
                        _ => {}
                    }
                }
            }

            EtherTypes::Ipv4 => {
                if let Some(v4packet) = Ipv4Packet::owned(p.payload().to_vec()) {
                    match v4packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            // handle when we return no new connections
                            if let Some((token, conn)) = icmp::handle_icmp_packet(reg, v4packet)
                                .map_err(HandlePacketError::from)?
                            {
                                conn_map.insert(token, conn);
                            };
                        }
                        IpNextHeaderProtocols::Udp => {
                            let udp_packet = UdpPacket::new(v4packet.payload()).unwrap();
                            // dhcp ? but again, we could send whatever on port 67 but hey
                            if udp_packet.get_destination() == 67 {
                                let mut dhcp_msg =
                                    match Message::decode(&mut Decoder::new(v4packet.payload())) {
                                        Ok(msg) => msg,
                                        Err(_) => {
                                            return Err(HandlePacketError(
                                                "error parsing dhcp packet".to_string(),
                                            ));
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
                                            return Err(HandlePacketError(
                                                "invalid dhcp message type".to_string(),
                                            ));
                                        }
                                    };
                                    opts.insert(DhcpOption::MessageType(response_type));
                                };
                                let mask = (!0u32 << (32 - conf.ip4.prefix_len as u32)).to_be();

                                dhcp_msg.set_yiaddr(conf.ip4.addr);
                                opts.insert(DhcpOption::SubnetMask(Ipv4Addr::BROADCAST));
                                opts.insert(DhcpOption::Router(vec![conf.ip4.guest_gw]));
                                opts.insert(DhcpOption::ServerIdentifier(conf.ip4.our_tap_addr));

                                if conf.ip4.guest_gw.to_bits() & mask
                                    != conf.ip4.addr.to_bits() & mask
                                {
                                    opts.insert(DhcpOption::ClasslessStaticRoute(vec![(
                                        Ipv4Net::new(conf.ip4.guest_gw, 32).unwrap(),
                                        conf.ip4.guest_gw.clone(),
                                    )]));
                                }

                                // eventually
                                dhcp_msg.set_opts(opts);
                                let mut msg_buf = Vec::new();
                                let mut enc = Encoder::new(&mut msg_buf);
                                dhcp_msg.encode(&mut enc).unwrap();

                                // do we build a new packet or use the existing one ?
                                tap_udp4_sent(
                                    conf,
                                    conf.ip4.our_tap_addr,
                                    67,
                                    conf.ip4.addr,
                                    68,
                                    msg_buf,
                                )
                                .unwrap();
                            }

                            // dhcp ?
                        }
                        IpNextHeaderProtocols::Tcp => {}
                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }
    Ok(())
}

// should i wrap it in an ethernet packet like i did with arp ?
// fn build_ipv4_packet(packet_data: &mut Vec<u8>) -> Option<Ipv4<'static>> {}

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

pub fn handle_tap_ethernet(
    ctx: &mut StreamConnCtx,
) -> Result<Vec<EthernetPacket<'static>>, io::Error> {
    let mut buf = [0u8; MAX_FRAME];
    let mut v4_packets: Vec<EthernetPacket<'static>> = Vec::new();
    let mut offset = 0;
    if ctx.partial_frame.len() > 0 {
        buf.clone_from_slice(ctx.partial_frame());
        offset += ctx.partial_frame.len();
    }
    let mut n = ctx.stream.read(&mut buf[offset..])?;

    while n > 4 {
        let l2len = u32::from_be_bytes(buf[offset..offset + 4].try_into().map_err(|e| {
            error!("failed to parse packet size: {e}");
            io::Error::new(io::ErrorKind::InvalidData, "failed to parse packet size")
        })?) as usize;

        // let l2len = usize::from_be_bytes(packet_size);
        if l2len > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Frame too large",
            ));
        }
        offset += 4;
        n -= 4;
        if let Some(packet) = EthernetPacket::owned(buf[offset..offset + l2len].to_vec()).take() {
            v4_packets.push(packet);
        };

        offset += l2len;
        n -= l2len;
        if l2len > buf[offset..].len() {
            ctx.partial_frame.clone_from_slice(&buf[offset..]);
        }
    }
    Ok(v4_packets)
}
