use std::net::{ UdpSocket, Ipv4Addr, SocketAddr };
use std::str::{ from_utf8, FromStr };
use std::io::Result as IoResult;
use log::{ info, debug };
use env_logger::init;
use std::env;

fn main() -> IoResult<()> {
    init();

    let glue_name = env::var("GLUE_NAME").unwrap_or_else(|_| "ns.example.com".to_string());
    let glue_ip = env::var("GLUE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let glue_ip: Ipv4Addr = glue_ip.parse().expect("Invalid GLUE_IP");

    let soa_name = env::var("SOA_NAME").unwrap_or_else(|_| "ns.example.com".to_string());
    let hostmaster = env
        ::var("HOSTMASTER")
        .unwrap_or_else(|_| "hostmaster.example.com".to_string());
    let serial: u32 = env
        ::var("SERIAL")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Invalid SERIAL");
    let refresh: u32 = env
        ::var("REFRESH")
        .unwrap_or_else(|_| "3600".to_string())
        .parse()
        .expect("Invalid REFRESH");
    let retry: u32 = env
        ::var("RETRY")
        .unwrap_or_else(|_| "1800".to_string())
        .parse()
        .expect("Invalid RETRY");
    let expire: u32 = env
        ::var("EXPIRE")
        .unwrap_or_else(|_| "604800".to_string())
        .parse()
        .expect("Invalid EXPIRE");
    let minimum: u32 = env
        ::var("MINIMUM")
        .unwrap_or_else(|_| "3600".to_string())
        .parse()
        .expect("Invalid MINIMUM");

    let socket = UdpSocket::bind("[::]:5053")?;
    let mut buf: [u8; 512];

    println!("RustyAlias Server Started on Port 5053/udp");

    loop {
        buf = [0; 512]; // Reinitialize buffer
        let (amt, src) = socket.recv_from(&mut buf)?;
        debug!("Received query from {}: {:?}", src, &buf[..amt]);
        handle_query(
            &buf[..amt],
            &socket,
            src,
            &glue_name,
            glue_ip,
            &soa_name,
            &hostmaster,
            serial,
            refresh,
            retry,
            expire,
            minimum
        )?;
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
    response.extend(&[0x81, 0x80]); // Flags: response, authoritative
    response.extend(&query[4..6]); // QDCOUNT

    if let Some((glue_name, glue_ip)) = glue {
        response.extend(&[0x00, 0x00]); // ANCOUNT
        response.extend(&[0x00, 0x01]); // NSCOUNT
        response.extend(&[0x00, 0x01]); // ARCOUNT

        let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
        response.extend(&query[12..question_end]); // Original question

        // Authority section (NS record)
        response.extend(&[0xC0, 0x0C]); // Pointer to the domain name in the question
        response.extend(&[0x00, 0x02]); // Type NS
        response.extend(&[0x00, 0x01]); // Class IN
        response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
        let ns_name_encoded = encode_domain_name(glue_name);
        response.extend(&(ns_name_encoded.len() as u16).to_be_bytes()); // RDLENGTH
        response.extend(ns_name_encoded); // RDATA

        // Additional section (A record for the glue name)
        let glue_name_encoded = encode_domain_name(glue_name);
        response.extend(&glue_name_encoded); // Glue name
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

fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    for part in name.split('.') {
        encoded.push(part.len() as u8);
        encoded.extend(part.as_bytes());
    }
    encoded.push(0); // End of the domain name
    encoded
}

fn build_soa_response(
    query: &[u8],
    soa_name: &str,
    hostmaster: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Vec<u8> {
    let mut response: Vec<u8> = Vec::with_capacity(512);
    response.extend(&query[0..2]); // Transaction ID
    response.extend(&[0x81, 0x80]); // Flags: response, authoritative
    response.extend(&query[4..6]); // QDCOUNT
    response.extend(&[0x00, 0x00]); // ANCOUNT
    response.extend(&[0x00, 0x01]); // NSCOUNT
    response.extend(&[0x00, 0x00]); // ARCOUNT

    let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
    response.extend(&query[12..question_end]); // Original Question

    // SOA Record
    response.extend(&[0xc0, 0x0c]); // Name pointer to the original question
    response.extend(&[0x00, 0x06]); // Type: SOA
    response.extend(&[0x00, 0x01]); // Class: IN
    response.extend(&[0x00, 0x00, 0x0e, 0x10]); // TTL: 3600 seconds
    let mut rdata = Vec::new();
    rdata.extend(encode_domain_name(soa_name));
    rdata.extend(encode_domain_name(hostmaster));
    rdata.extend(&serial.to_be_bytes());
    rdata.extend(&refresh.to_be_bytes());
    rdata.extend(&retry.to_be_bytes());
    rdata.extend(&expire.to_be_bytes());
    rdata.extend(&minimum.to_be_bytes());
    response.extend(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    response.extend(rdata);

    debug!("Built SOA response: {:?}", response);
    response
}

fn handle_query(
    query: &[u8],
    socket: &UdpSocket,
    src: SocketAddr,
    glue_name: &str,
    glue_ip: Ipv4Addr,
    soa_name: &str,
    hostmaster: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32
) -> IoResult<()> {
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
        } else if domain.ends_with(glue_name) {
            // Respond with SOA for intermediate subdomains
            info!("Client [{}] query for intermediate subdomain [{}] - returning SOA", src, domain);
            let response: Vec<u8> = build_soa_response(
                query,
                soa_name,
                hostmaster,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            );
            socket.send_to(&response, src)?;
        } else {
            info!("Client [{}] failed to resolve [{}]", src, domain);
            // Respond with an appropriate SOA record for non-existent domain (NXDOMAIN)
            let response: Vec<u8> = build_soa_response(
                query,
                soa_name,
                hostmaster,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            );
            socket.send_to(&response, src)?;
        }
    } else {
        debug!("Failed to parse query: {:?}", query);
    }
    Ok(())
}