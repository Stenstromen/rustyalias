use super::ip_parser::interpret_ip;
use super::response::{
    build_refused_response, build_response, build_soa_response, build_txt_response, SoaParams,
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
    if let Some(domain) = parse_query(query) {
        debug!("Parsed domain: {domain}");
        debug!("GLUE_NAME: {}", config.glue_name);

        if !is_in_zone(&domain, &config.glue_name) && !is_version_query(&domain) {
            info!("Client [{src}] refused [{domain}] (out of zone)");
            let response = build_refused_response(query);
            socket.send_to(&response, src)?;
            return Ok(());
        }

        if domain.eq_ignore_ascii_case(&config.glue_name) {
            info!(
                "Client [{}] resolved [{}] to [{}]",
                src, domain, config.glue_ip
            );
            let response = build_response(query, Some((&config.glue_name, config.glue_ip)), None);
            socket.send_to(&response, src)?;
        } else if is_version_query(&domain) {
            info!("Client [{src}] requested version TXT record");
            let nameandversion = format!("RustyAlias v{}", config.version);
            let response = build_txt_response(query, &nameandversion);
            socket.send_to(&response, src)?;
        } else if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{src}] resolved [{domain}] to [{ip:?}]");
            let response = build_response(query, None, Some(ip));
            socket.send_to(&response, src)?;
        } else {
            info!("Client [{src}] query for intermediate subdomain [{domain}] - returning SOA");
            let soa_params = SoaParams {
                soa_name: &config.soa_name,
                hostmaster: &config.hostmaster,
                serial: config.serial,
                refresh: config.refresh,
                retry: config.retry,
                expire: config.expire,
                minimum: config.minimum,
            };
            let response = build_soa_response(query, &soa_params);
            socket.send_to(&response, src)?;
        }
    } else {
        debug!("Failed to parse query: {query:?}");
    }
    Ok(())
}

fn is_version_query(domain: &str) -> bool {
    domain.eq_ignore_ascii_case("version")
        || domain.eq_ignore_ascii_case("ver")
        || domain.eq_ignore_ascii_case("v")
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
    if let Some(domain) = parse_query(query) {
        debug!("Parsed domain: {domain}");
        debug!("GLUE_NAME: {}", config.glue_name);

        if !is_in_zone(&domain, &config.glue_name) && !is_version_query(&domain) {
            info!("Client [{src}] refused [{domain}] (out of zone)");
            return Ok(build_refused_response(query));
        }

        let response = if domain.eq_ignore_ascii_case(&config.glue_name) {
            info!(
                "Client [{}] resolved [{}] to [{}]",
                src, domain, config.glue_ip
            );
            build_response(query, Some((&config.glue_name, config.glue_ip)), None)
        } else if is_version_query(&domain) {
            info!("Client [{src}] requested version TXT record");
            build_txt_response(query, &config.version)
        } else if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{src}] resolved [{domain}] to [{ip:?}]");
            build_response(query, None, Some(ip))
        } else {
            info!("Client [{src}] query for intermediate subdomain [{domain}] - returning SOA");
            let soa_params = SoaParams {
                soa_name: &config.soa_name,
                hostmaster: &config.hostmaster,
                serial: config.serial,
                refresh: config.refresh,
                retry: config.retry,
                expire: config.expire,
                minimum: config.minimum,
            };
            build_soa_response(query, &soa_params)
        };
        Ok(response)
    } else {
        debug!("Failed to parse query: {query:?}");
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
