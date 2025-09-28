#![allow(non_upper_case_globals)]
use clap::Parser;
use libpasst::*;
use log::{error, info};
use mio::net::{UnixListener, UnixStream};
use mio::{Events, Interest, Poll, Token};
use pnet::packet::ethernet::EtherTypes::Arp;
use pnet::packet::ethernet::EthernetPacket;
use std::io::{self};
use std::net::Shutdown;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;
use std::io::Write;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Socket path for Unix domain socket
    #[arg(short = 's', long = "socket-path", default_value = "/tmp/my_socket")]
    socket_path: String,
}

// ammar: test after arp
#[tokio::main]
async fn main() -> io::Result<()> {
    unsafe {
        setup_sig_handler(exit_handler as usize, libc::SIGTERM);
        setup_sig_handler(exit_handler as usize, libc::SIGQUIT);
    }
    let args = Args::parse();
    let mut ctx = Context::new();
    let socket_path = args.socket_path.as_str();
    let _ = std::fs::remove_file(socket_path);
    let mut listener = UnixListener::bind(socket_path)?;
    let mut poll = Poll::new()?;
    let tap_ev = EpollRef::new(listener.as_raw_fd(), 32);
    poll.registry()
        .register(&mut listener, Token(tap_ev.0), Interest::READABLE)?;
    let mut events = Events::with_capacity(16);
    let (tx, mut rx) = mpsc::channel::<EthernetPacket<'static>>(100);

    tokio::spawn(async move {
        // should wait on this before it declares it unready
        let mut stream: &UnixStream;
        loop {
            if let Some(s) = ctx.stream.as_ref() {
                stream = s;
                break;
            }
            info!("the stream is not ready yet, sleeping for two seconds");
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        while let Some(packet) = rx.recv().await {
            match packet.get_ethertype() {
                Arp => {
                    let arp_packet = ArpPacket::new(packet.payload()).unwrap();
                    if let Err(e) = stream.write(arp_packet.packet()) {}; // handle this
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
                    let mut v4_packets = Vec::new();
                    match handle_tap_ethernet(ctx.stream_fd, &mut ctx.partial_tap_frame) {
                        Ok((packets, partial_frame)) => {
                            ctx.partial_tap_frame = partial_frame;
                            v4_packets = packets;
                        }
                        Err(e) => {
                            error!("error receicing ethernet packages {e}");
                            drop(tx.clone());
                        }
                    }
                    handle_packets(tx.clone(), &mut v4_packets).await;
                }
                _ => {}
            }
        }
    }
}

fn handle_tap_ethernet(
    stream_fd: RawFd,
    partial_tap_frame: &mut Vec<u8>,
) -> Result<(Vec<EthernetPacket<'static>>, Vec<u8>), io::Error> {
    let mut buf = [0u8; MAX_FRAME];
    let mut v4_packets: Vec<EthernetPacket<'static>> = Vec::new();
    let mut offset = 0;
    if partial_tap_frame.len() > 0 {
        buf.clone_from_slice(&partial_tap_frame);
        offset += partial_tap_frame.len();
    }
    let mut n = recv_nonblock(stream_fd, &mut buf, offset).unwrap();

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
        if let Some(packet) = EthernetPacket::owned(buf[offset..l2len].to_vec()).take() {
            v4_packets.push(packet);
        };

        offset += l2len;
        n -= l2len;
        if l2len > buf[offset..].len() {
            partial_tap_frame.clone_from_slice(&mut buf[offset..]);
        }
    }
    Ok((v4_packets, partial_tap_frame.to_vec()))
}
