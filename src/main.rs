use std::net::{UdpSocket, Ipv4Addr, SocketAddr};
use std::str::{from_utf8, FromStr};
use std::io::Result as IoResult;
use log::{info, debug};
use env_logger::init;
use std::env;

fn main() -> IoResult<()> {
    init();

    let glue_name = env::var("GLUE_NAME").unwrap_or_else(|_| "ns.example.com".to_string());
    let glue_ip = env::var("GLUE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let glue_ip: Ipv4Addr = glue_ip.parse().expect("Invalid GLUE_IP");

    let socket: UdpSocket = UdpSocket::bind("0.0.0.0:5053")?;
    let mut buf: [u8; 512];

    println!("RustyAlias Server Started on Port 5053/udp");

    loop {
        buf = [0; 512];  // Reinitialize buffer
        let (amt, src) = socket.recv_from(&mut buf)?;
        debug!("Received query from {}: {:?}", src, &buf[..amt]);
        handle_query(&buf[..amt], &socket, src, &glue_name, glue_ip)?;
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

    if domain.is_empty() {
        debug!("Domain name parsed as empty.");
        return None;
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

fn build_response(query: &[u8], glue: Option<(&str, Ipv4Addr)>, ip: Option<Ipv4Addr>) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::with_capacity(512);

    response.extend(&query[0..2]); // ID
    response.extend(&[0x81, 0x80]); // Flags
    response.extend(&query[4..6]); // QDCOUNT

    if let Some((glue_name, glue_ip)) = glue {
        response.extend(&[0x00, 0x01]); // ANCOUNT
        response.extend(&[0x00, 0x00]); // NSCOUNT
        response.extend(&[0x00, 0x01]); // ARCOUNT

        let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
        response.extend(&query[12..question_end]); // Original question

        // Answer section (NS record)
        response.extend(&[0xC0, 0x0C]); // Pointer to the domain name in the question
        response.extend(&[0x00, 0x02]); // Type NS
        response.extend(&[0x00, 0x01]); // Class IN
        response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        let mut ns_name_encoded = Vec::new();
        for part in glue_name.split('.') {
            ns_name_encoded.push(part.len() as u8);
            ns_name_encoded.extend(part.as_bytes());
        }
        ns_name_encoded.push(0); // Null terminator for the domain name
        response.extend(&(ns_name_encoded.len() as u16).to_be_bytes()); // RDLENGTH
        response.extend(ns_name_encoded); // RDATA

        // Additional section (A record for the glue name)
        let glue_name_parts: Vec<&str> = glue_name.split('.').collect();
        for part in glue_name_parts {
            response.push(part.len() as u8);
            response.extend(part.as_bytes());
        }
        response.push(0); // Null terminator for the glue name
        response.extend(&[0x00, 0x01]); // Type A
        response.extend(&[0x00, 0x01]); // Class IN
        response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        response.extend(&[0x00, 0x04]); // RDLENGTH
        response.extend(&glue_ip.octets()); // RDATA
    } else if let Some(ip) = ip {
        response.extend(&[0x00, 0x01]); // ANCOUNT
        response.extend(&[0x00, 0x00]); // NSCOUNT
        response.extend(&[0x00, 0x00]); // ARCOUNT

        let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
        response.extend(&query[12..question_end]); // Original question

        // Answer section (A record)
        response.extend(&[0xC0, 0x0C]); // Pointer to the domain name in the question
        response.extend(&[0x00, 0x01]); // Type A
        response.extend(&[0x00, 0x01]); // Class IN
        response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        response.extend(&[0x00, 0x04]); // RDLENGTH
        response.extend(&ip.octets()); // RDATA
    }

    debug!("Built response: {:?}", response);
    response
}

fn handle_query(query: &[u8], socket: &UdpSocket, src: SocketAddr, glue_name: &str, glue_ip: Ipv4Addr) -> IoResult<()> {
    if let Some(domain) = parse_query(query) {
        debug!("Parsed domain: {}", domain);
        debug!("GLUE_NAME: {}", glue_name);
        if domain.eq_ignore_ascii_case(glue_name) {
            info!("Client [{}] resolved [{}] to [{}]", src, domain, glue_ip);
            let response: Vec<u8> = build_response(query, Some((glue_name, glue_ip)), None);
            socket.send_to(&response, src)?;
        } else if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{}] resolved [{}] to [{}]", src, domain, ip);
            let response: Vec<u8> = build_response(query, None, Some(ip));
            socket.send_to(&response, src)?;
        } else {
            info!("Client [{}] failed to resolve [{}]", src, domain);
        }
    } else {
        debug!("Failed to parse query: {:?}", query);
    }
    Ok(())
}