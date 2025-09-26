#![allow(non_upper_case_globals)]
use libpasst::*;
use log::error;
use mio::net::UnixListener;
use mio::{Events, Interest, Poll, Token};
use pnet::packet::ethernet::EtherTypes::Arp;
use pnet::packet::ethernet::EthernetPacket;
use std::io::{self};
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;
use std::io::Write;
use tokio::sync::mpsc;

// ammar: test after arp
#[tokio::main]
async fn main() -> io::Result<()> {
    unsafe {
        setup_sig_handler(exit_handler as usize, libc::SIGTERM);
        setup_sig_handler(exit_handler as usize, libc::SIGQUIT);
    }
    let mut ctx = Context::new();
    // ammar: turn into a flag
    let socket_path = "/tmp/my_socket";
    let _ = std::fs::remove_file(socket_path);
    let mut listener = UnixListener::bind(socket_path)?;
    let mut poll = Poll::new()?;
    let tap_ev = EpollRef::new(listener.as_raw_fd(), 32);
    poll.registry()
        .register(&mut listener, Token(tap_ev.0), Interest::READABLE)?;
    let mut events = Events::with_capacity(16);
    // ammar: channel length
    let (tx, mut rx) = mpsc::channel::<EthernetPacket<'static>>(100);
    let mut tx_shutdown = Some(tx.clone());

    tokio::spawn(async move {
        // should wait on this before it declares it unready
        let mut stream = ctx.stream.as_ref().expect("");
        while let Some(packet) = rx.recv().await {
            match packet.get_ethertype() {
                Arp => {
                    let arp_packet = ArpPacket::new(packet.payload()).unwrap();
                    if let Err(e) = stream.write(arp_packet.packet()) {};
                }
                _ => {}
            }
        }
        match stream.shutdown(Shutdown::Both) {
            Ok(()) => {}
            Err(e) => {
                error!("error shutting down stream {e}");
            }
        };
    });

    loop {
        poll.poll(&mut events, Some(Duration::from_secs(5)))?;
        for ev in events.iter() {
            let (_, typ) = EpollRef::from_u64(usize::from(ev.token())).unpack();
            match typ {
                32 => {
                    let (mut stream, _) = listener.accept().unwrap();

                    let socket_ep_ref = EpollRef::new(stream.as_raw_fd(), 10);
                    poll.registry().register(
                        &mut stream,
                        Token(socket_ep_ref.0),
                        Interest::READABLE,
                    )?;
                    ctx.stream_fd = stream.as_raw_fd();
                    ctx.stream = Some(stream);
                }
                10 => {
                    let mut buf = [0u8; MAX_FRAME];
                    let mut v4_packets: Vec<EthernetPacket<'static>> = Vec::new();
                    let mut offset = 0;
                    if ctx.partial_tap_frame.len() > 0 {
                        buf.clone_from_slice(&ctx.partial_tap_frame);
                        offset += ctx.partial_tap_frame.len();
                    }
                    let n = recv_nonblock(ctx.stream_fd.as_raw_fd(), &mut buf, offset).unwrap();
                    while n > 4 {
                        let l2len =
                            usize::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
                        if l2len > MAX_FRAME {
                            drop(tx_shutdown.take());
                        }
                        offset += 4;
                        let packet = EthernetPacket::owned(buf[offset..l2len].to_vec()).unwrap();
                        v4_packets.push(packet);
                        offset += l2len;
                        if l2len > buf[offset..].len() {
                            ctx.partial_tap_frame.clone_from_slice(&mut buf[offset..]);
                        }
                    }
                    handle_packets(tx.clone(), &mut v4_packets).await;
                }
                _ => {}
            }
        }
    }
}
