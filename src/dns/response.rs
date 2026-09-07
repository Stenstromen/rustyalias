use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;
const RCODE_NOERROR: u8 = 0;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;
const EDNS_UDP_SIZE: u16 = 1232;
const TTL_SOA: u32 = 3600;
const TTL_RR: u32 = 60;

const OFFSET_ANCOUNT: usize = 6;
const OFFSET_NSCOUNT: usize = 8;
const OFFSET_ARCOUNT: usize = 10;

pub struct ZoneParams<'a> {
    pub zone: &'a str,
    pub ns_name: &'a str,
    pub glue_ip: Ipv4Addr,
    pub hostmaster: &'a str,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// Apex SPF TXT value, if published.
    pub spf: Option<&'a str>,
}

enum Owner<'a> {
    /// Compression pointer to the QNAME at offset 12.
    Question,
    Name(&'a str),
}

/// QR=1, OPCODE copied, AA as requested, TC=0, RD copied, RA=0, RCODE as requested.
fn response_flags(query: &[u8], aa: bool, rcode: u8) -> [u8; 2] {
    let q2 = query.get(2).copied().unwrap_or(0);
    let opcode = q2 & 0b0111_1000;
    let rd = q2 & 0b0000_0001;
    let aa_bit = if aa { 0b0000_0100 } else { 0 };
    [0b1000_0000 | opcode | aa_bit | rd, rcode & 0x0f]
}

pub fn question_section_end(query: &[u8]) -> Option<usize> {
    if query.len() < 12 {
        return None;
    }
    let null_offset = query[12..].iter().position(|&x| x == 0)?;
    let end = 12 + null_offset + 5;
    (end <= query.len()).then_some(end)
}

pub fn parse_qtype_qclass(query: &[u8]) -> Option<(u16, u16)> {
    let end = question_section_end(query)?;
    Some((
        u16::from_be_bytes([query[end - 4], query[end - 3]]),
        u16::from_be_bytes([query[end - 2], query[end - 1]]),
    ))
}

fn query_has_opt(query: &[u8]) -> bool {
    if query.len() < 12 {
        return false;
    }
    let arcount = u16::from_be_bytes([query[10], query[11]]);
    if arcount == 0 {
        return false;
    }
    let Some(end) = question_section_end(query) else {
        return false;
    };
    let rest = &query[end..];
    // Typical query OPT: root name, type 41.
    rest.len() >= 11 && rest[0] == 0 && rest[1] == 0 && rest[2] == 0x29
}

fn bump_count(buf: &mut [u8], offset: usize) {
    let n = u16::from_be_bytes([buf[offset], buf[offset + 1]]).saturating_add(1);
    buf[offset..offset + 2].copy_from_slice(&n.to_be_bytes());
}

fn maybe_append_opt(response: &mut Vec<u8>, query: &[u8]) {
    if !query_has_opt(query) || response.len() < 12 {
        return;
    }
    bump_count(response, OFFSET_ARCOUNT);
    response.push(0); // root
    response.extend(TYPE_OPT.to_be_bytes());
    response.extend(EDNS_UDP_SIZE.to_be_bytes());
    response.extend(&[0, 0, 0, 0]); // EXT RCODE / version / flags
    response.extend(0u16.to_be_bytes()); // RDLEN
}

struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    fn with_question(query: &[u8], aa: bool, rcode: u8) -> Option<Self> {
        let end = question_section_end(query)?;
        let mut buf = Vec::with_capacity(512);
        buf.extend(&query[0..2]);
        buf.extend(response_flags(query, aa, rcode));
        buf.extend(&query[4..6]); // QDCOUNT
        buf.extend([0, 0, 0, 0, 0, 0]); // AN / NS / AR
        buf.extend(&query[12..end]);
        Some(Self { buf })
    }

    fn add_rr(&mut self, count_offset: usize, owner: Owner<'_>, typ: u16, ttl: u32, rdata: &[u8]) {
        match owner {
            Owner::Question => self.buf.extend([0xC0, 0x0C]),
            Owner::Name(name) => self.buf.extend(encode_domain_name(name)),
        }
        self.buf.extend(typ.to_be_bytes());
        self.buf.extend(CLASS_IN.to_be_bytes());
        self.buf.extend(ttl.to_be_bytes());
        self.buf.extend((rdata.len() as u16).to_be_bytes());
        self.buf.extend(rdata);
        bump_count(&mut self.buf, count_offset);
    }

    fn add_soa(&mut self, count_offset: usize, owner: Owner<'_>, params: &ZoneParams<'_>) {
        let mut rdata = Vec::new();
        rdata.extend(encode_domain_name(params.ns_name));
        rdata.extend(encode_domain_name(params.hostmaster));
        rdata.extend(params.serial.to_be_bytes());
        rdata.extend(params.refresh.to_be_bytes());
        rdata.extend(params.retry.to_be_bytes());
        rdata.extend(params.expire.to_be_bytes());
        rdata.extend(params.minimum.to_be_bytes());
        self.add_rr(count_offset, owner, TYPE_SOA, TTL_SOA, &rdata);
    }

    fn add_ns(&mut self, count_offset: usize, owner: Owner<'_>, ns_name: &str) {
        let rdata = encode_domain_name(ns_name);
        self.add_rr(count_offset, owner, TYPE_NS, TTL_RR, &rdata);
    }

    fn add_a(&mut self, count_offset: usize, owner: Owner<'_>, ip: Ipv4Addr) {
        self.add_rr(count_offset, owner, TYPE_A, TTL_RR, &ip.octets());
    }

    fn add_aaaa(&mut self, count_offset: usize, owner: Owner<'_>, ip: Ipv6Addr) {
        self.add_rr(count_offset, owner, TYPE_AAAA, TTL_RR, &ip.octets());
    }

    fn add_txt(&mut self, txt: &str) {
        let bytes = txt.as_bytes();
        let len = bytes.len().min(255);
        let mut rdata = Vec::with_capacity(len + 1);
        rdata.push(len as u8);
        rdata.extend(&bytes[..len]);
        self.add_rr(OFFSET_ANCOUNT, Owner::Question, TYPE_TXT, TTL_RR, &rdata);
    }

    fn add_in_bailiwick_glue(&mut self, params: &ZoneParams<'_>) {
        if ns_needs_glue(params) {
            self.add_a(OFFSET_ARCOUNT, Owner::Name(params.ns_name), params.glue_ip);
        }
    }

    fn finish(mut self, query: &[u8]) -> Vec<u8> {
        maybe_append_opt(&mut self.buf, query);
        debug!("Built response: {:?}", self.buf);
        self.buf
    }
}

fn ns_needs_glue(params: &ZoneParams<'_>) -> bool {
    let ns = params.ns_name.trim_end_matches('.');
    let zone = params.zone.trim_end_matches('.');
    if ns.eq_ignore_ascii_case(zone) {
        return true;
    }
    ns.len() > zone.len() + 1
        && ns.as_bytes()[ns.len() - zone.len() - 1] == b'.'
        && ns[ns.len() - zone.len()..].eq_ignore_ascii_case(zone)
}

pub fn names_eq(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for part in name.split('.') {
            encoded.push(part.len() as u8);
            encoded.extend(part.as_bytes());
        }
    }
    encoded.push(0);
    encoded
}

fn error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(query.len().saturating_add(11));
    buf.extend(&query[0..2]);
    buf.extend(response_flags(query, false, rcode));
    buf.extend(&query[4..6]);
    buf.extend([0, 0, 0, 0, 0, 0]);
    if let Some(end) = question_section_end(query) {
        buf.extend(&query[12..end]);
    }
    maybe_append_opt(&mut buf, query);
    debug!("Built error response rcode={rcode}: {buf:?}");
    buf
}

pub fn build_refused_response(query: &[u8]) -> Vec<u8> {
    error_response(query, RCODE_REFUSED)
}

pub fn build_notimp_response(query: &[u8]) -> Vec<u8> {
    error_response(query, RCODE_NOTIMP)
}

fn nodata(query: &[u8], params: &ZoneParams<'_>) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };
    // RFC 2308: negative TTL is the SOA minimum; owner is the zone apex, not QNAME.
    msg.add_soa(OFFSET_NSCOUNT, Owner::Name(params.zone), params);
    msg.finish(query)
}

pub fn build_nodata_response(query: &[u8], params: &ZoneParams<'_>) -> Vec<u8> {
    nodata(query, params)
}

pub fn build_txt_response(query: &[u8], txt_data: &str) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };
    msg.add_txt(txt_data);
    msg.finish(query)
}

pub fn build_apex_response(query: &[u8], qtype: u16, params: &ZoneParams<'_>) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };

    match qtype {
        TYPE_SOA => {
            msg.add_soa(OFFSET_ANCOUNT, Owner::Question, params);
            msg.add_ns(OFFSET_NSCOUNT, Owner::Question, params.ns_name);
            msg.add_in_bailiwick_glue(params);
        }
        TYPE_NS => {
            msg.add_ns(OFFSET_ANCOUNT, Owner::Question, params.ns_name);
            msg.add_in_bailiwick_glue(params);
        }
        TYPE_A => {
            msg.add_a(OFFSET_ANCOUNT, Owner::Question, params.glue_ip);
        }
        TYPE_TXT => {
            let Some(spf) = params.spf else {
                return nodata(query, params);
            };
            msg.add_txt(spf);
        }
        TYPE_ANY => {
            msg.add_soa(OFFSET_ANCOUNT, Owner::Question, params);
            msg.add_ns(OFFSET_ANCOUNT, Owner::Question, params.ns_name);
            msg.add_a(OFFSET_ANCOUNT, Owner::Question, params.glue_ip);
            if let Some(spf) = params.spf {
                msg.add_txt(spf);
            }
            msg.add_in_bailiwick_glue(params);
        }
        TYPE_AAAA => return nodata(query, params),
        _ => return nodata(query, params),
    }

    msg.finish(query)
}

pub fn build_address_response(
    query: &[u8],
    qtype: u16,
    ip: (Option<Ipv4Addr>, Option<Ipv6Addr>),
    params: &ZoneParams<'_>,
) -> Vec<u8> {
    let want_a = qtype == TYPE_A || qtype == TYPE_ANY;
    let want_aaaa = qtype == TYPE_AAAA || qtype == TYPE_ANY;
    let v4 = ip.0.filter(|_| want_a);
    let v6 = ip.1.filter(|_| want_aaaa);

    if v4.is_none() && v6.is_none() {
        return nodata(query, params);
    }

    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };
    if let Some(ip) = v4 {
        msg.add_a(OFFSET_ANCOUNT, Owner::Question, ip);
    }
    if let Some(ip) = v6 {
        msg.add_aaaa(OFFSET_ANCOUNT, Owner::Question, ip);
    }
    msg.finish(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(resp: &[u8]) -> (bool, bool, bool, u8) {
        let aa = resp[2] & 0x04 != 0;
        let rd = resp[2] & 0x01 != 0;
        let ra = resp[3] & 0x80 != 0;
        let rcode = resp[3] & 0x0f;
        (aa, rd, ra, rcode)
    }

    #[test]
    fn authoritative_flags_set_aa_clear_ra_copy_rd() {
        let mut query = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(encode_domain_name("example.com"));
        query.extend(TYPE_A.to_be_bytes());
        query.extend(CLASS_IN.to_be_bytes());

        let params = ZoneParams {
            zone: "example.com",
            ns_name: "ns.example.com",
            glue_ip: Ipv4Addr::new(1, 2, 3, 4),
            hostmaster: "hostmaster.example.com",
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 3600,
            spf: Some("v=spf1 -all"),
        };
        let resp = build_apex_response(&query, TYPE_A, &params);
        let (aa, rd, ra, rcode) = flags(&resp);
        assert!(aa, "AA must be set on in-zone answers");
        assert!(rd, "RD must be copied from the query");
        assert!(!ra, "RA must be clear; this is not a recursive server");
        assert_eq!(rcode, 0);
    }

    #[test]
    fn refused_is_not_authoritative() {
        let mut query = vec![0, 1, 0x00, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(encode_domain_name("evil.com"));
        query.extend(TYPE_A.to_be_bytes());
        query.extend(CLASS_IN.to_be_bytes());
        let resp = build_refused_response(&query);
        let (aa, rd, ra, rcode) = flags(&resp);
        assert!(!aa);
        assert!(!rd);
        assert!(!ra);
        assert_eq!(rcode, RCODE_REFUSED);
    }
}
