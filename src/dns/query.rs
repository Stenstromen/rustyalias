use super::ip_parser::interpret_ip;
use super::response::{build_response, build_soa_response, SoaParams};
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
        debug!("Parsed domain: {}", domain);
        debug!("GLUE_NAME: {}", config.glue_name);

        if domain.eq_ignore_ascii_case(&config.glue_name) {
            info!(
                "Client [{}] resolved [{}] to [{}]",
                src, domain, config.glue_ip
            );
            let response = build_response(query, Some((&config.glue_name, config.glue_ip)), None);
            socket.send_to(&response, src)?;
        } else if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{}] resolved [{}] to [{:?}]", src, domain, ip);
            let response = build_response(query, None, Some(ip));
            socket.send_to(&response, src)?;
        } else if domain.ends_with(&config.glue_name) {
            info!(
                "Client [{}] query for intermediate subdomain [{}] - returning SOA",
                src, domain
            );
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
        } else {
            info!("Client [{}] failed to resolve [{}]", src, domain);
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
        debug!("Failed to parse query: {:?}", query);
    }
    Ok(())
}

pub fn parse_query(query: &[u8]) -> Option<String> {
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

pub fn handle_query_internal(query: &[u8], src: SocketAddr, config: &Config) -> IoResult<Vec<u8>> {
    if let Some(domain) = parse_query(query) {
        debug!("Parsed domain: {}", domain);
        debug!("GLUE_NAME: {}", config.glue_name);

        let response = if domain.eq_ignore_ascii_case(&config.glue_name) {
            info!(
                "Client [{}] resolved [{}] to [{}]",
                src, domain, config.glue_ip
            );
            build_response(query, Some((&config.glue_name, config.glue_ip)), None)
        } else if let Some(ip) = interpret_ip(&domain) {
            info!("Client [{}] resolved [{}] to [{:?}]", src, domain, ip);
            build_response(query, None, Some(ip))
        } else {
            info!("Client [{}] failed to resolve [{}]", src, domain);
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
        debug!("Failed to parse query: {:?}", query);
        Ok(Vec::new())
    }
}
