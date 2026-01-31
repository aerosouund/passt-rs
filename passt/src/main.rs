#![allow(non_upper_case_globals)]
use clap::Parser;
use libpasst::conf::Conf;
use libpasst::muxer::{ConnEnum, StreamConnCtx};
use libpasst::{handle_packets, handle_tap_ethernet};
use log::{debug, error, info};
use mio::net::UnixListener;
use mio::{Events, Interest, Poll, Token};

use std::collections::HashMap;
use std::io::{self};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

mod conf;

fn main() -> io::Result<()> {
    unsafe {
        setup_sig_handler(exit_handler as usize, libc::SIGTERM);
        setup_sig_handler(exit_handler as usize, libc::SIGQUIT);
    }
    let args = Args::parse();
    let socket_path = args.socket_path.as_str();
    let _ = std::fs::remove_file(socket_path);

    let mut listener = UnixListener::bind(socket_path)?;

    let mut conn_map: HashMap<Token, ConnEnum> = HashMap::new();

    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)?;

    conn_map.insert(Token(0), ConnEnum::SocketListener(listener));

    let mut c = Conf::default(); // todo: parse from arguments

    let mut events = Events::with_capacity(16);
    loop {
        poll.poll(&mut events, Some(Duration::from_secs(5)))?;
        for ev in events.iter() {
            let mut conn = if let Some(conn) = conn_map.remove(&ev.token()) {
                conn
            } else {
                continue;
            };
            match conn {
                ConnEnum::SocketListener(ref mut listener_stream) => {
                    let (mut stream, _) = listener_stream.accept().unwrap();
                    let stream_fd = stream.as_raw_fd() as usize;
                    if c.tap_fd != 0 {
                        c.tap_fd = stream.as_raw_fd();
                    };
                    poll.registry()
                        .register(&mut stream, Token(stream_fd), Interest::READABLE)?;
                    conn_map.insert(
                        Token(stream_fd),
                        ConnEnum::Stream(StreamConnCtx {
                            stream,
                            partial_frame: Vec::new(),
                        }),
                    );
                }
                ConnEnum::Stream(ref mut stream_ctx) => {
                    let mut packets = handle_tap_ethernet(stream_ctx)?;
                    if let Err(e) = handle_packets(
                        &c,
                        poll.registry(),
                        stream_ctx.stream(),
                        &mut packets,
                        &mut conn_map,
                    ) {
                        error!("{}", e);
                    }
                }
                _ => {}
            }
        }
    }
}

// SAFETY: This is safe to call because all it does is setup signal interrupts
unsafe fn setup_sig_handler(handler: usize, signal: libc::c_int) {
    let mut sa: libc::sigaction = std::mem::zeroed();

    sa.sa_sigaction = handler;
    sa.sa_flags = 0;

    libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
    libc::sigaction(signal, &sa, std::ptr::null_mut());
}

pub extern "C" fn exit_handler(signum: libc::c_int) {
    unsafe {
        libc::exit(signum);
    }
}
