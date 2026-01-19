use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

pub fn create_socket(
    domain: i32,      // AF_INET, AF_INET6, AF_UNIX, etc.
    sock_type: i32,   // SOCK_STREAM, SOCK_DGRAM, etc.
    sock_option: i32, // e.g., SOCK_NONBLOCK | SOCK_CLOEXEC
    protocol: i32,    // IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP
) -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(domain, sock_type | sock_option, protocol) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

pub fn sockaddr_in_from(addr: &Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: 0, // this won't work on linux
        sin_family: libc::AF_INET as u8,
        sin_port: libc::htons(port),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.octets()),
        },
        sin_zero: [0; 8],
    }
}

pub fn set_socketopt(
    socket_fd: i32,
    level: i32,
    opt: i32,
    opt_val: i32,
    opt_val_size: usize,
) -> io::Result<RawFd> {
    unsafe {
        libc::setsockopt(
            socket_fd,
            level,
            opt,
            &opt_val as *const _ as *const libc::c_void,
            opt_val_size as libc::socklen_t,
        );
    }
    Ok(socket_fd)
}
