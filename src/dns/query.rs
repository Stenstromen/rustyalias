use super::ip_parser::interpret_ip;
use super::response::{
    build_address_response, build_apex_response, build_nodata_response, build_notimp_response,
    build_refused_response, build_txt_response, names_eq, parse_qtype_qclass, ZoneParams, TYPE_ANY,
    TYPE_TXT,
};
use crate::config::Config;
use log::{debug, info};
use std::io::Result as IoResult;
use std::net::{SocketAddr, UdpSocket};
use std::str::from_utf8;

pub fn handle_query(
    query: &[u8],
    socket: &UdpSocket,
    src: SocketAddr,
    config: &Config,
) -> IoResult<()> {
    let response = handle_query_internal(query, src, config)?;
    if !response.is_empty() {
        socket.send_to(&response, src)?;
    }
    Ok(())
}

fn is_version_query(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("version")
        || domain.eq_ignore_ascii_case("ver")
        || domain.eq_ignore_ascii_case("v")
}

fn opcode(query: &[u8]) -> u8 {
    query.get(2).map(|b| (b >> 3) & 0x0f).unwrap_or(0)
}

fn zone_params(config: &Config) -> ZoneParams<'_> {
    ZoneParams {
        zone: &config.glue_name,
        ns_name: &config.soa_name,
        glue_ip: config.glue_ip,
        hostmaster: &config.hostmaster,
        serial: config.serial,
        refresh: config.refresh,
        retry: config.retry,
        expire: config.expire,
        minimum: config.minimum,
    }
}

/// Returns true if `domain` equals `zone` or is a strict subdomain of `zone`,
/// using case-insensitive comparison and respecting label boundaries
/// (so `fakens.addr.se` does not match the zone `ns.addr.se`).
pub fn is_in_zone(domain: &str, zone: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');

    if zone.is_empty() {
        return false;
    }
    if domain.eq_ignore_ascii_case(zone) {
        return true;
    }
    if domain.len() <= zone.len() + 1 {
        return false;
    }
    let split_at = domain.len() - zone.len();
    if domain.as_bytes()[split_at - 1] != b'.' {
        return false;
    }
    domain[split_at..].eq_ignore_ascii_case(zone)
}

pub fn parse_query(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        debug!("Query too short: {}", query.len());
        return None;
    }

    let qdcount: u16 = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        debug!("Invalid QDCOUNT: {qdcount}");
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

pub fn handle_query_internal(query: &[u8], src: SocketAddr, config: &Config) -> IoResult<Vec<u8>> {
    if opcode(query) != 0 {
        info!("Client [{src}] OPCODE {} not implemented", opcode(query));
        return Ok(build_notimp_response(query));
    }

    let Some(domain) = parse_query(query) else {
        debug!("Failed to parse query: {query:?}");
        return Ok(Vec::new());
    };
    let (qtype, qclass) = match parse_qtype_qclass(query) {
        Some(pair) => pair,
        None => {
            debug!("Failed to parse QTYPE/QCLASS: {query:?}");
            return Ok(Vec::new());
        }
    };

    debug!("Parsed domain: {domain} QTYPE={qtype} QCLASS={qclass}");
    debug!("GLUE_NAME: {}", config.glue_name);

    if qclass != 1 {
        info!("Client [{src}] refused [{domain}] (qclass {qclass})");
        return Ok(build_refused_response(query));
    }

    if !is_in_zone(&domain, &config.glue_name) && !is_version_query(&domain) {
        info!("Client [{src}] refused [{domain}] (out of zone)");
        return Ok(build_refused_response(query));
    }

    let params = zone_params(config);

    let response = if is_version_query(&domain) {
        if qtype == TYPE_TXT || qtype == TYPE_ANY {
            info!("Client [{src}] requested version TXT record");
            build_txt_response(query, &format!("RustyAlias v{}", config.version))
        } else if is_in_zone(&domain, &config.glue_name) {
            build_nodata_response(query, &params)
        } else {
            build_refused_response(query)
        }
    } else if names_eq(&domain, &config.glue_name) {
        info!("Client [{src}] apex query [{domain}] type {qtype}");
        build_apex_response(query, qtype, &params)
    } else if names_eq(&domain, &config.soa_name) && is_in_zone(&domain, &config.glue_name) {
        info!(
            "Client [{}] nameserver hostname [{}] -> [{}]",
            src, domain, config.glue_ip
        );
        build_address_response(query, qtype, (Some(config.glue_ip), None), &params)
    } else if let Some(ip) = interpret_ip(&domain) {
        info!("Client [{src}] resolved [{domain}] to [{ip:?}]");
        build_address_response(query, qtype, ip, &params)
    } else {
        info!("Client [{src}] query for intermediate subdomain [{domain}] - NODATA");
        build_nodata_response(query, &params)
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::response::{TYPE_A, TYPE_AAAA, TYPE_NS, TYPE_SOA};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> Config {
        Config {
            glue_name: "nip.nu".to_string(),
            glue_ip: Ipv4Addr::new(37, 27, 198, 249),
            soa_name: "ns1.addr.se".to_string(),
            hostmaster: "hostmaster.nip.nu".to_string(),
            serial: 1,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum: 3600,
            version: "1.8.1".to_string(),
            rate_limit_seconds: 0,
            rate_limit_requests: 0,
        }
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        dns_query_with(name, qtype, 0x0100, false)
    }

    fn dns_query_with(name: &str, qtype: u16, flags: u16, edns: bool) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend([0x12, 0x34]);
        q.extend(flags.to_be_bytes());
        q.extend([0, 1, 0, 0, 0, 0]);
        q.extend(if edns { [0, 1] } else { [0, 0] });
        q.extend(crate::dns::response::encode_domain_name(name));
        q.extend(qtype.to_be_bytes());
        q.extend(1u16.to_be_bytes());
        if edns {
            q.push(0);
            q.extend(41u16.to_be_bytes());
            q.extend(1232u16.to_be_bytes());
            q.extend([0, 0, 0, 0]);
            q.extend(0u16.to_be_bytes());
        }
        q
    }

    fn src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    fn ancount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }
    fn nscount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[8], resp[9]])
    }
    fn arcount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[10], resp[11]])
    }
    fn aa(resp: &[u8]) -> bool {
        resp[2] & 0x04 != 0
    }
    fn ra(resp: &[u8]) -> bool {
        resp[3] & 0x80 != 0
    }
    fn rcode(resp: &[u8]) -> u8 {
        resp[3] & 0x0f
    }

    fn contains_type(resp: &[u8], typ: u16) -> bool {
        let needle = typ.to_be_bytes();
        resp.windows(2).any(|w| w == needle)
    }

    #[test]
    fn in_zone_exact_match() {
        assert!(is_in_zone("ns.addr.se", "ns.addr.se"));
        assert!(is_in_zone("NS.ADDR.SE", "ns.addr.se"));
        assert!(is_in_zone("ns.addr.se.", "ns.addr.se"));
        assert!(is_in_zone("ns.addr.se", "ns.addr.se."));
    }

    #[test]
    fn in_zone_subdomains() {
        assert!(is_in_zone("app.ns.addr.se", "ns.addr.se"));
        assert!(is_in_zone("a.b.c.ns.addr.se", "ns.addr.se"));
        assert!(is_in_zone("192-168-1-1.ns.addr.se", "ns.addr.se"));
    }

    #[test]
    fn out_of_zone_is_rejected() {
        let zone = "ns.addr.se";
        for domain in [
            "version.bind",
            "id.server",
            "hostname.bind",
            "google.com",
            "cloudflare.com",
            "uu.nl",
            "longttl.aaexp1.research.syssec.cispa.de",
            "com",
            "example.com",
            "addr.se",
            "fakens.addr.se",
            "ns1.addr.se",
        ] {
            assert!(
                !is_in_zone(domain, zone),
                "domain {domain} unexpectedly classified as in-zone of {zone}"
            );
        }
    }

    #[test]
    fn version_query_recognised() {
        assert!(is_version_query("version"));
        assert!(is_version_query("ver"));
        assert!(is_version_query("v"));
        assert!(is_version_query("VERSION"));
        assert!(!is_version_query("version.bind"));
        assert!(!is_version_query("verify"));
    }

    #[test]
    fn ip_hostname_is_authoritative_a() {
        let cfg = test_config();
        let q = dns_query("127.0.0.1.nip.nu", TYPE_A);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert!(!ra(&resp));
        assert_eq!(rcode(&resp), 0);
        assert_eq!(ancount(&resp), 1);
        assert!(contains_type(&resp, TYPE_A));
        assert_eq!(&resp[resp.len() - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn ipv4_hostname_aaaa_is_nodata() {
        let cfg = test_config();
        let q = dns_query("127.0.0.1.nip.nu", TYPE_AAAA);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert_eq!(rcode(&resp), 0);
        assert_eq!(ancount(&resp), 0);
        assert_eq!(nscount(&resp), 1);
        assert!(contains_type(&resp, TYPE_SOA));
    }

    #[test]
    fn apex_soa_is_in_answer() {
        let cfg = test_config();
        let q = dns_query("nip.nu", TYPE_SOA);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert_eq!(ancount(&resp), 1);
        assert!(contains_type(&resp, TYPE_SOA));
        assert!(contains_type(&resp, TYPE_NS));
    }

    #[test]
    fn apex_ns_is_in_answer_without_out_of_zone_glue() {
        let cfg = test_config();
        let q = dns_query("nip.nu", TYPE_NS);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert_eq!(ancount(&resp), 1);
        assert_eq!(nscount(&resp), 0);
        assert_eq!(arcount(&resp), 0);
        assert!(contains_type(&resp, TYPE_NS));
    }

    #[test]
    fn apex_a_returns_glue_ip() {
        let cfg = test_config();
        let q = dns_query("nip.nu", TYPE_A);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert_eq!(ancount(&resp), 1);
        assert_eq!(&resp[resp.len() - 4..], &[37, 27, 198, 249]);
    }

    #[test]
    fn out_of_zone_ns_hostname_is_refused() {
        let cfg = test_config();
        let q = dns_query("ns1.addr.se", TYPE_A);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(!aa(&resp));
        assert_eq!(rcode(&resp), 5);
    }

    #[test]
    fn in_zone_nameserver_hostname_has_a() {
        let mut cfg = test_config();
        cfg.soa_name = "ns.nip.nu".to_string();
        let q = dns_query("ns.nip.nu", TYPE_A);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert!(aa(&resp));
        assert_eq!(ancount(&resp), 1);
        assert_eq!(&resp[resp.len() - 4..], &[37, 27, 198, 249]);
    }

    #[test]
    fn edns_opt_is_echoed() {
        let cfg = test_config();
        let q = dns_query_with("127.0.0.1.nip.nu", TYPE_A, 0x0100, true);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert_eq!(arcount(&resp), 1);
        assert!(contains_type(&resp, crate::dns::response::TYPE_OPT));
    }

    #[test]
    fn rd_is_copied_from_query() {
        let cfg = test_config();
        let q = dns_query_with("127.0.0.1.nip.nu", TYPE_A, 0x0000, false);
        let resp = handle_query_internal(&q, src(), &cfg).unwrap();
        assert_eq!(resp[2] & 0x01, 0);
        assert!(aa(&resp));
    }
}
