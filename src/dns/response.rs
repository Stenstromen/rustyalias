use std::net::{Ipv4Addr, Ipv6Addr};
use log::debug;

pub fn build_response(
    query: &[u8],
    glue: Option<(&str, Ipv4Addr)>,
    ip: Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)>,
) -> Vec<u8> {
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
    } else if let Some((ipv4, ipv6)) = ip {
        let answer_count = ipv4.is_some() as u16 + ipv6.is_some() as u16;
        response.extend(&answer_count.to_be_bytes()); // ANCOUNT
        response.extend(&[0x00, 0x00]); // NSCOUNT
        response.extend(&[0x00, 0x00]); // ARCOUNT

        let question_end = 12 + query[12..].iter().position(|&x| x == 0).unwrap() + 5;
        response.extend(&query[12..question_end]); // Original question

        // Add IPv4 record if present
        if let Some(ipv4_addr) = ipv4 {
            response.extend(&[0xC0, 0x0C]); // Pointer to the domain name
            response.extend(&[0x00, 0x01]); // Type A
            response.extend(&[0x00, 0x01]); // Class IN
            response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
            response.extend(&[0x00, 0x04]); // RDLENGTH
            response.extend(&ipv4_addr.octets()); // RDATA
        }

        // Add IPv6 record if present
        if let Some(ipv6_addr) = ipv6 {
            response.extend(&[0xC0, 0x0C]); // Pointer to the domain name
            response.extend(&[0x00, 0x1C]); // Type AAAA
            response.extend(&[0x00, 0x01]); // Class IN
            response.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL
            response.extend(&[0x00, 0x10]); // RDLENGTH
            response.extend(&ipv6_addr.octets()); // RDATA
        }
    }

    debug!("Built response: {:?}", response);
    response
}

pub struct SoaParams<'a> {
    pub soa_name: &'a str,
    pub hostmaster: &'a str,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

pub fn build_soa_response(
    query: &[u8],
    params: &SoaParams,
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
    rdata.extend(encode_domain_name(params.soa_name));
    rdata.extend(encode_domain_name(params.hostmaster));
    rdata.extend(&params.serial.to_be_bytes());
    rdata.extend(&params.refresh.to_be_bytes());
    rdata.extend(&params.retry.to_be_bytes());
    rdata.extend(&params.expire.to_be_bytes());
    rdata.extend(&params.minimum.to_be_bytes());
    
    response.extend(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    response.extend(rdata);

    debug!("Built SOA response: {:?}", response);
    response
}

pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    for part in name.split('.') {
        encoded.push(part.len() as u8);
        encoded.extend(part.as_bytes());
    }
    encoded.push(0); // End of the domain name
    encoded
} 