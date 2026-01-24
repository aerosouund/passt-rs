use dhcproto::Decodable;
use dhcproto::v4::{Decoder, Message};
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
use pnet::packet::udp::UdpPacket;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::sync::{Arc, RwLock};

use crate::icmp::IcmpError;
use crate::muxer::ConnEnum;

pub const MAX_FRAME: usize = 65535 + 4;

pub mod flow;
pub mod fwd;
pub mod icmp;
pub mod muxer;
pub mod socket;
pub mod udp;

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
    reg: &Registry,
    stream: &mut UnixStream,
    packets: &mut Vec<EthernetPacket<'static>>,
    conn_map: &RwLock<HashMap<mio::Token, ConnEnum>>,
) -> Result<(), io::Error> {
    for p in packets.drain(..) {
        match p.get_ethertype() {
            EtherTypes::Arp => {
                if let Some(final_packet) = handle_arp_packet(&mut p.packet().to_vec()) {
                    let _ = stream
                        .write(final_packet.packet())
                        .map_err(|e| error!("{}", e));
                };
            }

            EtherTypes::Ipv4 => {
                if let Some(v4packet) = Ipv4Packet::owned(p.packet().to_vec()) {
                    match v4packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            let _ = icmp::handle_icmp_packet(reg, v4packet, conn_map)
                                .map_err(HandlePacketError::from);
                        }
                        IpNextHeaderProtocols::Udp => {
                            let udp_packet = UdpPacket::new(v4packet.payload()).unwrap();
                            // dhcp ? but again, we could send whatever on port 67 but hey
                            if udp_packet.get_destination() == 67 {
                                let dhcp_msg =
                                    Message::decode(&mut Decoder::new(v4packet.payload()));
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
        let packet_size: [u8; 8] = buf[offset..offset + 4].try_into().map_err(|e| {
            error!("failed to parse packet size {e}");
            io::Error::new(io::ErrorKind::InvalidData, "failed to parse packet size")
        })?;
        let l2len = usize::from_be_bytes(packet_size);
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
