use crate::conf::{Conf, Mode};
use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use pnet::packet::{MutablePacket, Packet, ipv4::MutableIpv4Packet, udp::MutableUdpPacket};
use std::fmt;
use std::io::IoSlice;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum UdpError {
    SysError(i32),
}
impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpError::SysError(e) => write!(f, "sys error: {}", e),
        }
    }
}

impl From<Errno> for UdpError {
    fn from(value: Errno) -> Self {
        UdpError::SysError(value as i32)
    }
}

impl std::error::Error for UdpError {}

pub fn handle_udp() -> Result<(), UdpError> {
    Ok(())
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
    // udp_packet.set_checksum(val); optional. maybe ?

    // does calling payload return the full packet or just the payload ? according to chatgpt its the whole
    // packet and in a format the os can handle but i am honestly not convinced
    let mut ip_packet = MutableIpv4Packet::new(udp_packet.payload_mut()).unwrap();
    ip_packet.set_source(src);
    ip_packet.set_destination(dest);

    let ip_pkt_raw = ip_packet.packet();
    let pkt_len: [u8; 1] = [ip_pkt_raw.len() as u8];
    send_single(conf, &[IoSlice::new(&pkt_len), IoSlice::new(&ip_pkt_raw)])
}

fn send_single(conf: &Conf, data: &[IoSlice]) -> Result<(), UdpError> {
    // a switch on the mode
    // transformation into an iovec
    match conf.mode {
        Mode::Passt => {
            let cmsgs: [ControlMessage<'_>; 0] = [];
            sendmsg(
                conf.tap_fd,
                data,
                &cmsgs,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )?;
            Ok(())
        }
        Mode::Pasta => Ok(()),
    }
}
