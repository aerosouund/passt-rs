use std::collections::HashMap;

use mio::net::{UnixListener, UnixStream};
use mio::Token;

#[derive(Default)]
pub struct Muxer {
    pub conn_map: HashMap<Token, ConnEnum>,
}

pub struct StreamConnCtx {
    pub stream: UnixStream,
    pub partial_frame: Vec<u8>, // can we use an array instead of vector ?
}

impl StreamConnCtx {
    pub fn stream(&mut self) -> &mut UnixStream {
        &mut self.stream
    }
    pub fn partial_frame(&mut self) -> &mut Vec<u8> {
        &mut self.partial_frame
    }
}

impl Muxer {
    pub fn new() -> Self {
        Self {
            conn_map: HashMap::new(),
        }
    }
}

pub enum ConnEnum {
    SocketListener(UnixListener),
    Stream(StreamConnCtx),
    TcpConn,
    EtherConn,
}
