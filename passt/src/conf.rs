#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Socket path for Unix domain socket
    #[arg(short = 's', long = "socket-path", default_value = "/tmp/my_socket")]
    socket_path: String,
}
