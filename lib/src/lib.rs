use flow::{flow_initiate_af, Flow, FlowType, Flowside, PifType, FLOWATSIDX, FLOWS};
use log::{debug, error, info};
use mio::net::UnixStream;
use muxer::StreamConnCtx;
use pnet::packet::arp::ArpOperation;
use pnet::packet::arp::MutableArpPacket;
use pnet::packet::ethernet::EtherTypes::Arp;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpType};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::io;
use std::io::{Read, Write};

use std::net::Ipv4Addr;
use std::os::fd::RawFd;

use crate::flow::StateIdx;

pub const MAX_FRAME: usize = 65535 + 4;

pub mod flow;
pub mod muxer;

#[derive(Default)]
pub struct Context {
    pub debug: i32,
    pub trace: i32,
    pub stream: Option<UnixStream>,
    pub stream_fd: RawFd,
    pub partial_tap_frame: Vec<u8>,
}

impl Context {
    pub fn new() -> Self {
        Context {
            debug: 0,
            trace: 0,
            partial_tap_frame: Vec::with_capacity(65535),
            ..Default::default()
        }
    }
}

pub struct PartialFrame(pub Vec<u8>);

#[allow(non_upper_case_globals)]
pub fn handle_packets(
    stream: &mut UnixStream,
    packets: &mut Vec<EthernetPacket<'static>>,
) -> Result<(), io::Error> {
    for p in packets.drain(..) {
        match p.get_ethertype() {
            Arp => {
                if let Some(final_packet) = handle_arp_packet(&mut p.packet().to_vec()) {
                    if let Err(e) = stream.write(final_packet.packet()) {
                        error!("{}", e.to_string())
                    }
                };
            }

            Ipv4 => {
                if let Some(v4packet) = Ipv4Packet::owned(p.packet().to_vec()) {
                    match v4packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            // should a table of flows and a table of indexes
                            // build the flowside from the icmp packet data
                            // i need to store the source and dest ips before turning it to an icmp packet
                            let src = v4packet.get_source();
                            let dest = v4packet.get_destination();
                            let icmp_packet =
                                IcmpPacket::owned(v4packet.payload().to_owned()).unwrap();

                            // is there a constant type i can compare with instead of this ?
                            if icmp_packet.get_icmp_type() != IcmpType::new(8) {
                                continue;
                            }

                            // SAFETY: we know that its an echo because we checked above
                            // so ID is certainly there
                            let arr =
                                unsafe { *(icmp_packet.payload().as_ptr() as *const [u8; 4]) };

                            let id = u16::from_be_bytes([arr[0], arr[1]]);

                            let flowside = Flowside::new(src, dest, id, id);
                            // make this a global
                            // get the sidx (the flow table index) from the flowside
                            if let Some(sidx) = FLOWATSIDX.get(&flowside) {
                                let f = unsafe { FLOWS.flows[sidx.flow_table_idx as usize] };
                                // nil check for f or flow init
                                new_icmp_flow(src, dest, id, id);
                            }

                            // check if the flow matches the flowside structrue we built in address and port, no port in icmp ?
                            // we use the id field in the icmp header for src/dst port
                            // then we need to turn the packet to an icmp packet?
                        }
                        IpNextHeaderProtocols::Tcp => {}
                        _ => {}
                    }
                }
                // should contain handling of ipv4 protos. icmp, tcp, udp.. etc
                //
            }
        }
    }
    Ok(())
}

fn new_icmp_flow(src: Ipv4Addr, dest: Ipv4Addr, srcport: u16, destport: u16) {
    // stupid ass asserts
    //
    let nextfree = unsafe { FLOWS.next_free.clone() };
    let mut f = unsafe { FLOWS.flows[FLOWS.next_free] };
    let mut ini_f = flow_initiate_af(&mut f, src, dest, srcport, destport, PifType::Host);

    match f.flow_common.pif[0] {
        PifType::Tap => {
            // fwd_nat_from_tap
            let target_pif = fwd_nat_from_tap(
                IpNextHeaderProtocols::Icmp,
                &mut ini_f,
                &mut f.side[1],
                srcport,
                destport,
            );
            f.flow_common.pif[1] = target_pif
        }
        PifType::Host => {
            // fwd_nat_from_host
        }
        PifType::Splice => {
            // fwd_nat_from_splice
        }
        _ => {}
    }
    if f.flow_common.pif[1] != PifType::Host {
        // error
    }
    f.flow_common.flow_type = FlowType::Ping;
    // initiaite flow sidx
    let sidx = StateIdx {
        sidei: 1,
        flow_table_idx: nextfree,
    };
    FLOWATSIDX.insert(f.side[1], sidx);

    // call l4 socket stuff ?
}
// ctx ?
fn fwd_nat_from_tap(
    proto: IpNextHeaderProtocol,
    ini: &mut Flowside,
    tgt: &mut Flowside,
    srcport: u16,
    destport: u16,
) -> PifType {
    // if dns ?
    if (proto == IpNextHeaderProtocols::Udp || proto == IpNextHeaderProtocols::Tcp) && srcport == 53
    {
        // handle dns
    }

    // from ini, check if its 4 or 6, loopback or an ip
    if ini.src.is_loopback() {
        ini.dest = Ipv4Addr::LOCALHOST
    } else if ini.src.is_unspecified() {
        tgt.dest = Ipv4Addr::UNSPECIFIED
    } else {
        tgt.dest = ini.src
    }
    tgt.destport = ini.srcport;
    // there was a condition on ipv4 here, since we are doing 4 only then by default its true
    tgt.src = Ipv4Addr::UNSPECIFIED;

    PifType::Host
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

pub extern "C" fn exit_handler(signum: libc::c_int) {
    unsafe {
        libc::exit(signum);
    }
}

// SAFETY: This is safe to call because all it does is setup signal interrupts
#[allow(clippy::missing_safety_doc)]
pub unsafe fn setup_sig_handler(handler: usize, signal: libc::c_int) {
    let mut sa: libc::sigaction = std::mem::zeroed();

    sa.sa_sigaction = handler;
    sa.sa_flags = 0;

    libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
    libc::sigaction(signal, &sa, std::ptr::null_mut());
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
