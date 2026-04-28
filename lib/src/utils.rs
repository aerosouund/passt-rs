use crate::TapError;
use crate::conf::{Conf, Mode};
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn, sendmsg};
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::MutableEthernetPacket;
use std::io::IoSlice;

pub(crate) fn send_ether(
    conf: &Conf,
    ethertype: EtherType,
    payload: &[u8],
) -> Result<(), TapError> {
    let pkt_len = payload.len();

    // should be the header size plus payload
    let mut ether_buffer = vec![0u8; MutableEthernetPacket::minimum_packet_size() + pkt_len];
    let mut ether_pkt = MutableEthernetPacket::new(&mut ether_buffer).unwrap();
    ether_pkt.set_ethertype(ethertype);
    ether_pkt.set_source(conf.our_tap_mac);
    ether_pkt.set_destination(conf.guest_mac);
    ether_pkt.set_payload(payload);

    let len_buf = (ether_pkt.packet().len() as u32).to_be_bytes();
    let p = ether_pkt.consume_to_immutable();
    let iovs = [IoSlice::new(p.packet()), IoSlice::new(&len_buf)];
    send_single(conf, &iovs)?;

    Ok(())
}

// ammar: ideally, this function should return the count of bytes sent
// and should handle whats sent not being equal to the length
fn send_single(conf: &Conf, data: &[IoSlice]) -> Result<(), std::io::Error> {
    let s: Option<&SockaddrIn> = None;
    match conf.mode {
        Mode::Passt => {
            let cmsgs: [ControlMessage<'_>; 0] = [];
            sendmsg(
                conf.tap_fd,
                data,
                &cmsgs,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                s,
            )?;
            Ok(())
        }
        Mode::Pasta => Ok(()),
    }
}
