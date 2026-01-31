use libpasst::conf::Mode;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Socket path for Unix domain socket
    #[arg(short = 's', long = "socket-path", default_value = "/tmp/my_socket")]
    socket_path: String,
    /// Passt mode
    #[arg(short = 'm', long = "mode", default_value = Mode::Passt)]
    socket_path: Mode,
}
