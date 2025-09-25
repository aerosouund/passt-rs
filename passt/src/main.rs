use libpasst::*;
use log::{error, info, warn};
use mio::net::UnixListener;
use mio::{Events, Interest, Poll, Token};
use nix::sys::socket::{recv, MsgFlags};
use pnet::packet::ethernet::EthernetPacket;
use std::net::Shutdown;
use std::time::Duration;

use std::io::{self};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

fn main() -> io::Result<()> {
    unsafe {
        setup_sig_handler(exit_handler as usize, libc::SIGTERM);
        setup_sig_handler(exit_handler as usize, libc::SIGQUIT);
    }
    let mut ctx = Context::new();
    let socket_path = "/tmp/my_socket";
    let _ = std::fs::remove_file(socket_path);
    let mut listener = UnixListener::bind(socket_path)?;
    let mut poll = Poll::new()?;
    let tap_ev = EpollRef::new(listener.as_raw_fd(), 32);
    poll.registry()
        .register(&mut listener, Token(tap_ev.0), Interest::READABLE)?;
    let mut events = Events::with_capacity(16);

    loop {
        poll.poll(&mut events, Some(Duration::from_secs(5)))?;
        for ev in events.iter() {
            let (fd, typ) = EpollRef::from_u64(usize::from(ev.token())).unpack();
            match typ {
                32 => {
                    let (mut stream, _) = listener.accept().unwrap();
                    let socket_ep_ref = EpollRef::new(stream.as_raw_fd(), 10);
                    poll.registry().register(
                        &mut stream,
                        Token(socket_ep_ref.0),
                        Interest::READABLE,
                    )?;
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
                    let stream_fd = ctx
                        .stream
                        .take()
                        .expect("stream should be set before calling recv_nonblock");

                    let n = recv_nonblock(stream_fd.as_raw_fd(), &mut buf, offset).unwrap();
                    while n > 4 {
                        let l2len =
                            usize::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
                        if l2len > MAX_FRAME {
                            match stream_fd.shutdown(Shutdown::Both) {
                                Ok(()) => {}
                                Err(e) => {
                                    error!("error shutting down stream {e}");
                                }
                            };
                        }
                        offset += 4;
                        let packet = EthernetPacket::owned(buf[offset..l2len].to_vec()).unwrap();
                        v4_packets.push(packet);
                        offset += l2len;
                        if l2len > buf[offset..].len() {
                            ctx.partial_tap_frame.clone_from_slice(&mut buf[offset..]);
                        }
                    }
                    handle_packets(v4_packets);
                }
                _ => {}
            }
        }
    }
}

fn recv_nonblock(fd: RawFd, buf: &mut [u8], offest: usize) -> nix::Result<usize> {
    loop {
        match recv(fd, &mut buf[offest..], MsgFlags::MSG_DONTWAIT) {
            Ok(n) => return Ok(n),
            Err(e) => return Err(e),
        }
    }
}

extern "C" fn exit_handler(signum: libc::c_int) {
    unsafe {
        libc::exit(signum);
    }
}

unsafe fn setup_sig_handler(handler: usize, signal: libc::c_int) {
    let mut sa: libc::sigaction = std::mem::zeroed();

    sa.sa_sigaction = handler as usize;
    sa.sa_flags = 0;

    libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
    libc::sigaction(signal, &sa, std::ptr::null_mut());
}
