#![allow(non_upper_case_globals)]
use clap::Parser;
use libpasst::muxer::{ConnEnum, Muxer, StreamConnCtx};
use libpasst::{exit_handler, handle_packets, setup_sig_handler, MAX_FRAME};
use log::{debug, error, info};
use mio::net::UnixListener;
use mio::{Events, Interest, Poll, Token};
use pnet::packet::ethernet::EthernetPacket;
use std::io::Read;

use std::io::{self};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Socket path for Unix domain socket
    #[arg(short = 's', long = "socket-path", default_value = "/tmp/my_socket")]
    socket_path: String,
}

fn main() -> io::Result<()> {
    unsafe {
        setup_sig_handler(exit_handler as usize, libc::SIGTERM);
        setup_sig_handler(exit_handler as usize, libc::SIGQUIT);
    }
    let args = Args::parse();
    let mut muxer = Muxer::new();
    let socket_path = args.socket_path.as_str();
    let _ = std::fs::remove_file(socket_path);

    let mut listener = UnixListener::bind(socket_path)?; // do we need the mio socket listener ?

    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;

    muxer
        .conn_map
        .insert(Token(0), ConnEnum::SocketListener(listener));

    let mut events = Events::with_capacity(16);
    loop {
        poll.poll(&mut events, Some(Duration::from_secs(5)))?;
        for ev in events.iter() {
            match muxer.conn_map.get_mut(&ev.token()) {
                Some(ConnEnum::SocketListener(listener_stream)) => {
                    let (mut stream, _) = listener_stream.accept().unwrap();
                    let stream_fd = stream.as_raw_fd() as usize;
                    poll.registry()
                        .register(&mut stream, Token(stream_fd), Interest::READABLE)?;
                    muxer.conn_map.insert(
                        Token(stream_fd),
                        ConnEnum::Stream(StreamConnCtx {
                            stream,
                            partial_frame: Vec::new(),
                        }),
                    );
                }
                Some(ConnEnum::Stream(ref mut stream_ctx)) => {
                    handle_tap_ethernet(stream_ctx)
                        .and_then(|mut packets| handle_packets(stream_ctx.stream(), &mut packets))
                        .unwrap_or_else(|e| error!("{}", e.to_string()));

                    if let Err(e) = handle_tap_ethernet(stream_ctx) {
                        error!("{}", e.to_string());
                        continue;
                    }
                }
                _ => {}
            }
        }
        // find a way to drop tx if the function returns an error
    }
}

fn handle_tap_ethernet(ctx: &mut StreamConnCtx) -> Result<Vec<EthernetPacket<'static>>, io::Error> {
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
