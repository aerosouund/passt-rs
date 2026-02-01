use clap::Parser;
use libpasst::conf::Mode;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    /// Socket path for Unix domain socket
    #[arg(short = 's', long = "socket-path", default_value = "/tmp/my_socket")]
    pub socket_path: String,
    /// Passt mode
    #[arg(short = 'm', long = "mode", value_enum, default_value = "passt")]
    pub mode: Mode,
}
