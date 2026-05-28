mod config;
mod dns;
mod rate_limit;

use config::Config;
use dns::query::{handle_query, handle_query_internal};
use env_logger::init;
use log::{debug, info};
use rate_limit::RateLimiter;
use std::io::prelude::*;
use std::io::Result as IoResult;
use std::net::{TcpListener, UdpSocket};
use std::thread;

fn main() -> IoResult<()> {
    init();
    let config = Config::from_env();
    let rate_limiter = RateLimiter::new(config.rate_limit_seconds, config.rate_limit_requests);

    let udp_socket = UdpSocket::bind("[::]:5053")?;
    let tcp_listener = TcpListener::bind("[::]:5053")?;

    println!("RustyAlias Server Started on Port 5053 (UDP/TCP)");
    if rate_limiter.is_enabled() {
        println!(
            "Rate limit: {} requests per {} second(s) per source IP",
            config.rate_limit_requests, config.rate_limit_seconds
        );
    }

    let udp_config = config.clone();
    let udp_rate_limiter = rate_limiter.clone();
    thread::spawn(move || loop {
        let mut buf = [0; 512];
        if let Ok((amt, src)) = udp_socket.recv_from(&mut buf) {
            debug!("Received UDP query from {}: {:?}", src, &buf[..amt]);
            if !udp_rate_limiter.check(src.ip()) {
                info!("Client [{src}] rate limited (UDP)");
                continue;
            }
            if let Err(e) = handle_query(&buf[..amt], &udp_socket, src, &udp_config) {
                eprintln!("Error handling UDP query: {e}");
            }
        }
    });

    for stream in tcp_listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let peer = stream.peer_addr()?;
                if !rate_limiter.check(peer.ip()) {
                    info!("Client [{peer}] rate limited (TCP)");
                    continue;
                }
                let mut length_buf = [0; 2];
                if stream.read_exact(&mut length_buf).is_ok() {
                    let length = u16::from_be_bytes(length_buf) as usize;
                    let mut buf = vec![0; length];

                    if stream.read_exact(&mut buf).is_ok() {
                        debug!("Received TCP query from {peer}: {buf:?}");
                        let response = handle_query_internal(&buf, peer, &config)?;
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
