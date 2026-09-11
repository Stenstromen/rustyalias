use super::dnssec::{self, DnssecKey};
use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_CDS: u16 = 59;
pub const TYPE_CDNSKEY: u16 = 60;
pub const TYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;
const RCODE_NOERROR: u8 = 0;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;
const DEFAULT_UDP_SIZE: usize = 512;
const EDNS_UDP_SIZE: u16 = 1232;
const TTL_SOA: u32 = 3600;
const TTL_RR: u32 = 60;

const OFFSET_ANCOUNT: usize = 6;
const OFFSET_NSCOUNT: usize = 8;
const OFFSET_ARCOUNT: usize = 10;

pub struct ZoneParams<'a> {
    pub zone: &'a str,
    /// SOA MNAME (primary nameserver).
    pub ns_name: &'a str,
    /// Full NS RRset advertised at the apex.
    pub ns_names: &'a [String],
    pub glue_ip: Ipv4Addr,
    pub glue_ip6: Option<Ipv6Addr>,
    pub hostmaster: &'a str,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// Apex SPF TXT value, if published.
    pub spf: Option<&'a str>,
    pub dnssec: Option<&'a DnssecKey>,
    /// EDNS DO bit from the query.
    pub do_bit: bool,
}

impl ZoneParams<'_> {
    fn sign(&self) -> bool {
        self.dnssec.is_some() && self.do_bit
    }

    fn apex_types(&self) -> Vec<u16> {
        let mut types = vec![TYPE_SOA, TYPE_NS, TYPE_A];
        if self.glue_ip6.is_some() {
            types.push(TYPE_AAAA);
        }
        if self.spf.is_some() {
            types.push(TYPE_TXT);
        }
        if self.dnssec.is_some() {
            types.extend([TYPE_DNSKEY, TYPE_CDS, TYPE_CDNSKEY]);
        }
        types
    }
}

#[derive(Clone, Copy)]
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
    opt_udp_payload_size(query).is_some()
}

/// Client OPT RR at the start of Additional, if present: (udp_size, do_bit).
fn parse_query_opt(query: &[u8]) -> Option<(usize, bool)> {
    if query.len() < 12 {
        return None;
    }
    let arcount = u16::from_be_bytes([query[10], query[11]]);
    if arcount == 0 {
        return None;
    }
    let end = question_section_end(query)?;
    let rest = &query[end..];
    // Typical query OPT: root name, type 41, CLASS = UDP size.
    if rest.len() >= 11 && rest[0] == 0 && rest[1] == 0 && rest[2] == 0x29 {
        let size = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let flags = u16::from_be_bytes([rest[7], rest[8]]);
        return Some((size.max(512), flags & 0x8000 != 0));
    }
    None
}

/// Client's advertised UDP payload size from OPT CLASS, if present.
fn opt_udp_payload_size(query: &[u8]) -> Option<usize> {
    parse_query_opt(query).map(|(size, _)| size)
}

/// True when the query OPT has the DNSSEC OK (DO) bit set.
pub fn query_dnssec_ok(query: &[u8]) -> bool {
    parse_query_opt(query).is_some_and(|(_, do_bit)| do_bit)
}

/// Maximum UDP response size for this query (512 without EDNS).
pub fn udp_response_limit(query: &[u8]) -> usize {
    opt_udp_payload_size(query)
        .unwrap_or(DEFAULT_UDP_SIZE)
        .min(EDNS_UDP_SIZE as usize)
}

fn bump_count(buf: &mut [u8], offset: usize) {
    let n = u16::from_be_bytes([buf[offset], buf[offset + 1]]).saturating_add(1);
    buf[offset..offset + 2].copy_from_slice(&n.to_be_bytes());
}

fn maybe_append_opt(response: &mut Vec<u8>, query: &[u8], dnssec_ok: bool) {
    if !query_has_opt(query) || response.len() < 12 {
        return;
    }
    bump_count(response, OFFSET_ARCOUNT);
    response.push(0); // root
    response.extend(TYPE_OPT.to_be_bytes());
    response.extend(EDNS_UDP_SIZE.to_be_bytes());
    response.push(0); // EXT RCODE
    response.push(0); // EDNS version
    let flags: u16 = if dnssec_ok { 0x8000 } else { 0 };
    response.extend(flags.to_be_bytes());
    response.extend(0u16.to_be_bytes()); // RDLEN
}

/// If `response` exceeds the UDP limit, set TC and keep only header + question (+ OPT).
pub fn maybe_truncate_udp(response: Vec<u8>, query: &[u8]) -> Vec<u8> {
    let limit = udp_response_limit(query);
    if response.len() <= limit {
        return response;
    }

    let Some(qend) = question_section_end(query) else {
        return response;
    };

    let mut truncated = Vec::with_capacity(qend + 16);
    truncated.extend(&response[0..2]); // ID
                                       // Preserve AA/RD/RCODE from the full response, set TC.
    let flags0 = response.get(2).copied().unwrap_or(0) | 0b0000_0010; // TC
    let flags1 = response.get(3).copied().unwrap_or(0);
    truncated.push(flags0);
    truncated.push(flags1);
    truncated.extend(&query[4..6]); // QDCOUNT
    truncated.extend([0, 0, 0, 0, 0, 0]); // AN / NS / AR cleared
    truncated.extend(&query[12..qend]);
    maybe_append_opt(&mut truncated, query, false);

    if truncated.len() > limit {
        // Drop OPT if the truncated packet is still too large.
        truncated.truncate(12 + (qend - 12));
        truncated[OFFSET_ARCOUNT] = 0;
        truncated[OFFSET_ARCOUNT + 1] = 0;
    }

    debug!(
        "Truncated UDP response from {} to {} bytes (limit {limit})",
        response.len(),
        truncated.len()
    );
    truncated
}

struct Rr<'a> {
    owner: Owner<'a>,
    typ: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

struct Msg<'a> {
    buf: Vec<u8>,
    answers: Vec<Rr<'a>>,
    authority: Vec<Rr<'a>>,
    additional: Vec<Rr<'a>>,
}

impl<'a> Msg<'a> {
    fn with_question(query: &[u8], aa: bool, rcode: u8) -> Option<Self> {
        let end = question_section_end(query)?;
        let mut buf = Vec::with_capacity(512);
        buf.extend(&query[0..2]);
        buf.extend(response_flags(query, aa, rcode));
        buf.extend(&query[4..6]); // QDCOUNT
        buf.extend([0, 0, 0, 0, 0, 0]); // AN / NS / AR
        buf.extend(&query[12..end]);
        Some(Self {
            buf,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        })
    }

    fn add_rr(&mut self, count_offset: usize, owner: Owner<'a>, typ: u16, ttl: u32, rdata: &[u8]) {
        let rr = Rr {
            owner,
            typ,
            ttl,
            rdata: rdata.to_vec(),
        };
        match count_offset {
            OFFSET_NSCOUNT => self.authority.push(rr),
            OFFSET_ARCOUNT => self.additional.push(rr),
            _ => self.answers.push(rr),
        }
    }

    fn add_soa(&mut self, count_offset: usize, owner: Owner<'a>, params: &ZoneParams<'_>) {
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

    fn add_ns(&mut self, count_offset: usize, owner: Owner<'a>, ns_name: &str) {
        let rdata = encode_domain_name(ns_name);
        self.add_rr(count_offset, owner, TYPE_NS, TTL_RR, &rdata);
    }

    fn add_ns_set(&mut self, count_offset: usize, params: &ZoneParams<'_>) {
        for name in params.ns_names {
            self.add_ns(count_offset, Owner::Question, name);
        }
    }

    fn add_a(&mut self, count_offset: usize, owner: Owner<'a>, ip: Ipv4Addr) {
        self.add_rr(count_offset, owner, TYPE_A, TTL_RR, &ip.octets());
    }

    fn add_aaaa(&mut self, count_offset: usize, owner: Owner<'a>, ip: Ipv6Addr) {
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

    fn add_dnskey(&mut self, params: &ZoneParams<'_>) {
        let Some(key) = params.dnssec else {
            return;
        };
        self.add_rr(
            OFFSET_ANCOUNT,
            Owner::Question,
            TYPE_DNSKEY,
            TTL_SOA,
            key.dnskey_rdata(),
        );
    }

    fn add_cds(&mut self, params: &ZoneParams<'_>) {
        let Some(key) = params.dnssec else {
            return;
        };
        let rdata = key.ds_rdata(params.zone);
        self.add_rr(OFFSET_ANCOUNT, Owner::Question, TYPE_CDS, TTL_SOA, &rdata);
    }

    fn add_cdnskey(&mut self, params: &ZoneParams<'_>) {
        let Some(key) = params.dnssec else {
            return;
        };
        self.add_rr(
            OFFSET_ANCOUNT,
            Owner::Question,
            TYPE_CDNSKEY,
            TTL_SOA,
            key.dnskey_rdata(),
        );
    }

    fn add_in_bailiwick_glue(&mut self, params: &ZoneParams<'a>) {
        for name in params.ns_names {
            if name_in_bailiwick(name, params.zone) {
                self.add_a(OFFSET_ARCOUNT, Owner::Name(name), params.glue_ip);
                if let Some(ip6) = params.glue_ip6 {
                    self.add_aaaa(OFFSET_ARCOUNT, Owner::Name(name), ip6);
                }
            }
        }
    }

    fn finish(mut self, query: &[u8], params: &ZoneParams<'_>) -> Vec<u8> {
        emit_section(&mut self.buf, OFFSET_ANCOUNT, self.answers, query, params);
        emit_section(&mut self.buf, OFFSET_NSCOUNT, self.authority, query, params);
        emit_section(
            &mut self.buf,
            OFFSET_ARCOUNT,
            self.additional,
            query,
            params,
        );
        maybe_append_opt(&mut self.buf, query, params.sign());
        debug!("Built response: {:?}", self.buf);
        self.buf
    }
}

fn owner_eq(a: Owner<'_>, b: Owner<'_>) -> bool {
    match (a, b) {
        (Owner::Question, Owner::Question) => true,
        (Owner::Name(x), Owner::Name(y)) => names_eq(x, y),
        _ => false,
    }
}

fn write_rr(buf: &mut Vec<u8>, owner: Owner<'_>, typ: u16, ttl: u32, rdata: &[u8]) {
    match owner {
        Owner::Question => buf.extend([0xC0, 0x0C]),
        Owner::Name(name) => buf.extend(encode_domain_name(name)),
    }
    buf.extend(typ.to_be_bytes());
    buf.extend(CLASS_IN.to_be_bytes());
    buf.extend(ttl.to_be_bytes());
    buf.extend((rdata.len() as u16).to_be_bytes());
    buf.extend(rdata);
}

fn emit_section(
    buf: &mut Vec<u8>,
    count_offset: usize,
    rrs: Vec<Rr<'_>>,
    query: &[u8],
    params: &ZoneParams<'_>,
) {
    let mut groups: Vec<Vec<Rr<'_>>> = Vec::new();
    for rr in rrs {
        if let Some(last) = groups.last_mut() {
            if owner_eq(last[0].owner, rr.owner) && last[0].typ == rr.typ {
                last.push(rr);
                continue;
            }
        }
        groups.push(vec![rr]);
    }

    for group in groups {
        let owner = group[0].owner;
        let typ = group[0].typ;
        let ttl = group[0].ttl;
        let mut rdatas: Vec<Vec<u8>> = group.into_iter().map(|r| r.rdata).collect();
        rdatas.sort();

        for rdata in &rdatas {
            write_rr(buf, owner, typ, ttl, rdata);
            bump_count(buf, count_offset);
        }

        if typ != TYPE_RRSIG {
            if let Some(key) = params.dnssec.filter(|_| params.do_bit) {
                let owner_wire = match owner {
                    Owner::Question => dnssec::owner_canonical_wire(query, true, None),
                    Owner::Name(name) => dnssec::owner_canonical_wire(query, false, Some(name)),
                };
                let rrsig = key.sign_rrsig(&owner_wire, typ, ttl, &rdatas, params.zone);
                write_rr(buf, owner, TYPE_RRSIG, ttl, &rrsig);
                bump_count(buf, count_offset);
            }
        }
    }
}

fn name_in_bailiwick(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if name.eq_ignore_ascii_case(zone) {
        return true;
    }
    name.len() > zone.len() + 1
        && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
        && name[name.len() - zone.len()..].eq_ignore_ascii_case(zone)
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
            encoded.extend(part.to_ascii_lowercase().as_bytes());
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
    maybe_append_opt(&mut buf, query, false);
    debug!("Built error response rcode={rcode}: {buf:?}");
    buf
}

pub fn build_refused_response(query: &[u8]) -> Vec<u8> {
    error_response(query, RCODE_REFUSED)
}

pub fn build_notimp_response(query: &[u8]) -> Vec<u8> {
    error_response(query, RCODE_NOTIMP)
}

fn nodata(query: &[u8], params: &ZoneParams<'_>, existing_types: &[u16]) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };
    // RFC 2308: negative TTL is the SOA minimum; owner is the zone apex, not QNAME.
    msg.add_soa(OFFSET_NSCOUNT, Owner::Name(params.zone), params);
    if params.sign() {
        let Some(end) = question_section_end(query) else {
            return msg.finish(query, params);
        };
        let qname = &query[12..end - 4];
        let types = dnssec::nsec_types(existing_types);
        let rdata = dnssec::nsec_rdata(qname, &types);
        msg.add_rr(
            OFFSET_NSCOUNT,
            Owner::Question,
            TYPE_NSEC,
            params.minimum,
            &rdata,
        );
    }
    msg.finish(query, params)
}

pub fn build_nodata_response(
    query: &[u8],
    params: &ZoneParams<'_>,
    existing_types: &[u16],
) -> Vec<u8> {
    nodata(query, params, existing_types)
}

pub fn build_txt_response(query: &[u8], txt_data: &str, params: &ZoneParams<'_>) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };
    msg.add_txt(txt_data);
    msg.finish(query, params)
}

pub fn build_apex_response(query: &[u8], qtype: u16, params: &ZoneParams<'_>) -> Vec<u8> {
    let Some(mut msg) = Msg::with_question(query, true, RCODE_NOERROR) else {
        return Vec::new();
    };

    match qtype {
        TYPE_SOA => {
            msg.add_soa(OFFSET_ANCOUNT, Owner::Question, params);
            msg.add_ns_set(OFFSET_NSCOUNT, params);
            msg.add_in_bailiwick_glue(params);
        }
        TYPE_NS => {
            msg.add_ns_set(OFFSET_ANCOUNT, params);
            msg.add_in_bailiwick_glue(params);
        }
        TYPE_A => {
            msg.add_a(OFFSET_ANCOUNT, Owner::Question, params.glue_ip);
        }
        TYPE_AAAA => {
            let Some(ip6) = params.glue_ip6 else {
                return nodata(query, params, &params.apex_types());
            };
            msg.add_aaaa(OFFSET_ANCOUNT, Owner::Question, ip6);
        }
        TYPE_TXT => {
            let Some(spf) = params.spf else {
                return nodata(query, params, &params.apex_types());
            };
            msg.add_txt(spf);
        }
        TYPE_DNSKEY => {
            if params.dnssec.is_none() {
                return nodata(query, params, &params.apex_types());
            }
            msg.add_dnskey(params);
        }
        TYPE_CDS => {
            if params.dnssec.is_none() {
                return nodata(query, params, &params.apex_types());
            }
            msg.add_cds(params);
        }
        TYPE_CDNSKEY => {
            if params.dnssec.is_none() {
                return nodata(query, params, &params.apex_types());
            }
            msg.add_cdnskey(params);
        }
        TYPE_NSEC => {
            if params.dnssec.is_none() {
                return nodata(query, params, &params.apex_types());
            }
            let Some(end) = question_section_end(query) else {
                return Vec::new();
            };
            let qname = &query[12..end - 4];
            let types = dnssec::nsec_types(&params.apex_types());
            let rdata = dnssec::nsec_rdata(qname, &types);
            msg.add_rr(
                OFFSET_ANCOUNT,
                Owner::Question,
                TYPE_NSEC,
                params.minimum,
                &rdata,
            );
        }
        TYPE_ANY => {
            msg.add_soa(OFFSET_ANCOUNT, Owner::Question, params);
            msg.add_ns_set(OFFSET_ANCOUNT, params);
            msg.add_a(OFFSET_ANCOUNT, Owner::Question, params.glue_ip);
            if let Some(ip6) = params.glue_ip6 {
                msg.add_aaaa(OFFSET_ANCOUNT, Owner::Question, ip6);
            }
            if let Some(spf) = params.spf {
                msg.add_txt(spf);
            }
            if params.dnssec.is_some() {
                msg.add_dnskey(params);
                msg.add_cds(params);
                msg.add_cdnskey(params);
            }
            msg.add_in_bailiwick_glue(params);
        }
        _ => return nodata(query, params, &params.apex_types()),
    }

    msg.finish(query, params)
}

fn address_types(ip: (Option<Ipv4Addr>, Option<Ipv6Addr>)) -> Vec<u16> {
    let mut types = Vec::new();
    if ip.0.is_some() {
        types.push(TYPE_A);
    }
    if ip.1.is_some() {
        types.push(TYPE_AAAA);
    }
    types
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
        return nodata(query, params, &address_types(ip));
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
    msg.finish(query, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(resp: &[u8]) -> (bool, bool, bool, bool, u8) {
        let aa = resp[2] & 0x04 != 0;
        let tc = resp[2] & 0x02 != 0;
        let rd = resp[2] & 0x01 != 0;
        let ra = resp[3] & 0x80 != 0;
        let rcode = resp[3] & 0x0f;
        (aa, tc, rd, ra, rcode)
    }

    fn sample_params<'a>(ns_names: &'a [String]) -> ZoneParams<'a> {
        ZoneParams {
            zone: "example.com",
            ns_name: "ns.example.com",
            ns_names,
            glue_ip: Ipv4Addr::new(1, 2, 3, 4),
            glue_ip6: Some("2001:db8::1".parse().unwrap()),
            hostmaster: "hostmaster.example.com",
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 3600,
            spf: Some("v=spf1 -all"),
            dnssec: None,
            do_bit: false,
        }
    }

    #[test]
    fn authoritative_flags_set_aa_clear_ra_copy_rd() {
        let mut query = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(encode_domain_name("example.com"));
        query.extend(TYPE_A.to_be_bytes());
        query.extend(CLASS_IN.to_be_bytes());

        let ns = vec!["ns.example.com".to_string()];
        let resp = build_apex_response(&query, TYPE_A, &sample_params(&ns));
        let (aa, tc, rd, ra, rcode) = flags(&resp);
        assert!(aa, "AA must be set on in-zone answers");
        assert!(!tc);
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
        let (aa, _tc, rd, ra, rcode) = flags(&resp);
        assert!(!aa);
        assert!(!rd);
        assert!(!ra);
        assert_eq!(rcode, RCODE_REFUSED);
    }

    #[test]
    fn truncate_sets_tc_when_over_limit() {
        let mut query = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(encode_domain_name("example.com"));
        query.extend(TYPE_ANY.to_be_bytes());
        query.extend(CLASS_IN.to_be_bytes());

        let ns = vec!["ns1.example.com".to_string(), "ns2.example.com".to_string()];
        let full = build_apex_response(&query, TYPE_ANY, &sample_params(&ns));
        // Force a tiny limit by crafting a non-EDNS query (512) — pad the
        // response artificially past 512 to exercise truncation.
        let mut oversized = full.clone();
        oversized.extend(vec![0u8; 600]);
        let truncated = maybe_truncate_udp(oversized, &query);
        let (_aa, tc, _rd, _ra, _rcode) = flags(&truncated);
        assert!(tc);
        assert!(truncated.len() <= DEFAULT_UDP_SIZE);
        assert_eq!(u16::from_be_bytes([truncated[6], truncated[7]]), 0); // ANCOUNT
    }

    #[test]
    fn name_in_bailiwick_checks_labels() {
        assert!(name_in_bailiwick("ns.example.com", "example.com"));
        assert!(name_in_bailiwick("example.com", "example.com"));
        assert!(!name_in_bailiwick("ns.addr.se", "nip.nu"));
        assert!(!name_in_bailiwick("fakens.example.com.evil", "example.com"));
    }
}
