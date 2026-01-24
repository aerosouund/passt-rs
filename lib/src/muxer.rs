use mio::net::{UnixListener, UnixStream};

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

pub enum ConnEnum {
    SocketListener(UnixListener),
    Stream(StreamConnCtx),
    // should there be another type that represents a unix stream directly ?
    TcpConn,
    EtherConn,
}
