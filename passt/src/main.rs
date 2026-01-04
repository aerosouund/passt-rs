#![allow(non_upper_case_globals)]
use clap::Parser;
use libpasst::muxer::{ConnEnum, Muxer, StreamConnCtx};
use libpasst::{exit_handler, handle_packets, handle_tap_ethernet, setup_sig_handler};
use log::{debug, error, info};
use mio::net::UnixListener;
use mio::{Events, Interest, Poll, Token};

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
    }
}
