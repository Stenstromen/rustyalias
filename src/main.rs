mod config;
mod dns;

use config::Config;
use dns::query::handle_query;
use env_logger::init;
use log::debug;
use std::io::Result as IoResult;
use std::net::UdpSocket;

fn main() -> IoResult<()> {
    init();
    
    let config = Config::from_env();
    let socket = UdpSocket::bind("[::]:5053")?;
    
    println!("RustyAlias Server Started on Port 5053/udp");

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf)?;
        debug!("Received query from {}: {:?}", src, &buf[..amt]);
        handle_query(&buf[..amt], &socket, src, &config)?;
    }
}
