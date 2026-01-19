use crate::flow::{Flowside, PifType};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::net::Ipv4Addr;

// ctx ?
pub fn fwd_nat_from_tap(
    proto: IpNextHeaderProtocol,
    ini: &mut Flowside,
    tgt: &mut Flowside,
    srcport: u16,
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
