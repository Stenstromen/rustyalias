mod config;
mod dns;

use config::Config;
use dns::query::{handle_query, handle_query_internal};
use env_logger::init;
use log::debug;
use std::io::prelude::*;
use std::io::Result as IoResult;
use std::net::{TcpListener, UdpSocket};
use std::thread;

fn main() -> IoResult<()> {
    init();
    let config = Config::from_env();

    let udp_socket = UdpSocket::bind("[::]:5053")?;
    let tcp_listener = TcpListener::bind("[::]:5053")?;

    println!("RustyAlias Server Started on Port 5053 (UDP/TCP)");

    let udp_config = config.clone();
    thread::spawn(move || loop {
        let mut buf = [0; 512];
        if let Ok((amt, src)) = udp_socket.recv_from(&mut buf) {
            debug!("Received UDP query from {}: {:?}", src, &buf[..amt]);
            if let Err(e) = handle_query(&buf[..amt], &udp_socket, src, &udp_config) {
                eprintln!("Error handling UDP query: {e}");
            }
        }
    });

    for stream in tcp_listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut length_buf = [0; 2];
                if stream.read_exact(&mut length_buf).is_ok() {
                    let length = u16::from_be_bytes(length_buf) as usize;
                    let mut buf = vec![0; length];

                    if stream.read_exact(&mut buf).is_ok() {
                        debug!(
                            "Received TCP query from {}: {:?}",
                            stream.peer_addr()?,
                            &buf
                        );
                        let response = handle_query_internal(&buf, stream.peer_addr()?, &config)?;
                        let response_len = (response.len() as u16).to_be_bytes();
                        stream.write_all(&response_len)?;
                        stream.write_all(&response)?;
                    }
                }
            }
            Err(e) => eprintln!("Error accepting TCP connection: {e}"),
        }
    }

    Ok(())
}
