use env_logger::init;
use log::{info, debug};
use::core::result::Result;
use std::io::Result as IoResult;
use std::str::{FromStr,from_utf8};
use std::net::{UdpSocket, Ipv4Addr, SocketAddr};

fn main() -> IoResult<()> {
    init();

    let socket: UdpSocket = UdpSocket::bind("0.0.0.0:5053")?;
    let mut buf: [u8; 512] = [0; 512];

    print!("RustyAlias Server Started on Port 5053/udp\n");

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        debug!("Received query from {}: {:?}", src, &buf[..amt]);
        handle_query(&buf[..amt], &socket, src)?;
    }
}

fn parse_query(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        debug!("Query too short: {}", query.len());
        return None;
    }

    let qdcount: u16 = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        debug!("Invalid QDCOUNT: {}", qdcount);
        return None;
    }

    let mut pos: usize = 12;
    let mut domain: String = String::new();
    while pos < query.len() {
        let len: usize = query[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > query.len() {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(from_utf8(&query[pos..pos + len]).ok()?);
        pos += len;
    }

    Some(domain)
}

fn interpret_ip(domain: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = domain.split('.').collect();
    debug!("Domain parts: {:?}", parts);

    if parts.len() >= 4 {
        for i in 0..=parts.len() - 4 {
            let potential_ip: String = parts[i..i + 4].join(".");
            if let Ok(ip) = Ipv4Addr::from_str(&potential_ip) {
                debug!("Parsed dotted decimal IP: {}", ip);
                return Some(ip);
            }
        }
    }

    for part in &parts {
        if part.len() == 8 {
            if let Ok(ip) = parse_hexadecimal_ip(part) {
                debug!("Parsed hexadecimal IP: {}", ip);
                return Some(ip);
            }
        }
        if let Some(ip) = parse_hyphenated_ip(part) {
            debug!("Parsed hyphenated IP: {}", ip);
            return Some(ip);
        }
    }

    debug!("Failed to interpret any parts as IP from domain: {}", domain);
    None
}

fn parse_hyphenated_ip(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('-').collect();
    debug!("Hyphenated IP parts: {:?}", parts);
    if parts.len() == 4 && parts.iter().all(|&p| p.parse::<u8>().is_ok()) {
        let ip_str: String = parts.join(".");
        if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
            return Some(ip);
        }
    } else if parts.len() > 4 {
        for i in 0..=parts.len() - 4 {
            if parts[i..i + 4].iter().all(|&p| p.parse::<u8>().is_ok()) {
                let ip_str = parts[i..i + 4].join(".");
                if let Ok(ip) = Ipv4Addr::from_str(&ip_str) {
                    return Some(ip);
                }
            }
        }
    }
    for part in parts.iter().filter(|&&p| p.len() == 8) {
        if let Ok(ip) = parse_hexadecimal_ip(part) {
            return Some(ip);
        }
    }
    None
}

fn parse_hexadecimal_ip(s: &str) -> Result<Ipv4Addr, ()> {
    debug!("Attempting to parse hex IP: {}", s);
    if s.len() != 8 {
        return Err(());
    }

    let mut octets: [u8; 4] = [0u8; 4];
    for i in 0..4 {
        let hex_str: &str = &s[2 * i..2 * i + 2];
        octets[i] = u8::from_str_radix(hex_str, 16).map_err(|_| ())?;
    }

    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn build_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::with_capacity(512);

    response.extend(&query[0..2]);
    response.extend(&[0x81, 0x80]);
    response.extend(&query[4..6]);
    response.extend(&[0x00, 0x01]);
    response.extend(&[0x00, 0x00, 0x00, 0x00]);
    let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
    response.extend(&query[12..question_end]);

    response.extend(&[0xC0, 0x0C]);
    response.extend(&[0x00, 0x01]);
    response.extend(&[0x00, 0x01]);
    response.extend(&[0x00, 0x00, 0x00, 0x3C]);
    response.extend(&[0x00, 0x04]);
    response.extend(&ip.octets());

    debug!("Built response: {:?}", response);
    response
}

fn handle_query(query: &[u8], socket: &UdpSocket, src: SocketAddr) -> IoResult<()> {
    if let Some(domain) = parse_query(query) {
        debug!("Parsed domain: {}", domain);
        if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{}] resolved [{}] to [{}]", src, domain, ip);
            let response: Vec<u8> = build_response(query, ip);
            socket.send_to(&response, src)?;
        } else {
            info!("Client [{}] failed to resolve [{}]", src, domain);
        }
    } else {
        debug!("Failed to parse query: {:?}", query);
    }
    Ok(())
}