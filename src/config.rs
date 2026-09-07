use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct Config {
    pub glue_name: String,
    pub glue_ip: Ipv4Addr,
    pub glue_ip6: Option<Ipv6Addr>,
    /// Primary nameserver (SOA MNAME).
    pub soa_name: String,
    /// Authoritative NS set advertised at the zone apex.
    pub ns_names: Vec<String>,
    pub hostmaster: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// Apex SPF TXT. Empty disables the record.
    pub spf: String,
    /// `_dmarc.<zone>` TXT. Empty disables the record.
    pub dmarc: String,
    pub version: String,
    pub rate_limit_seconds: u64,
    pub rate_limit_requests: u32,
}

impl Config {
    pub fn from_env() -> Self {
        // Baked in at compile time from Cargo.toml; never falls back to "unknown".
        let version = env!("CARGO_PKG_VERSION").to_string();

        let soa_name = env::var("SOA_NAME").unwrap_or_else(|_| "ns.example.com".to_string());
        let ns_names = parse_ns_names(env::var("NS_NAMES").ok(), &soa_name);

        Self {
            glue_name: env::var("GLUE_NAME").unwrap_or_else(|_| "ns.example.com".to_string()),
            glue_ip: env::var("GLUE_IP")
                .unwrap_or_else(|_| "127.0.0.1".to_string())
                .parse()
                .expect("Invalid GLUE_IP"),
            glue_ip6: match env::var("GLUE_IP6") {
                Ok(s) if !s.trim().is_empty() => Some(s.parse().expect("Invalid GLUE_IP6")),
                _ => None,
            },
            soa_name,
            ns_names,
            hostmaster: env::var("HOSTMASTER")
                .unwrap_or_else(|_| "hostmaster.example.com".to_string()),
            serial: env::var("SERIAL")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .expect("Invalid SERIAL"),
            refresh: env::var("REFRESH")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("Invalid REFRESH"),
            retry: env::var("RETRY")
                .unwrap_or_else(|_| "1800".to_string())
                .parse()
                .expect("Invalid RETRY"),
            expire: env::var("EXPIRE")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .expect("Invalid EXPIRE"),
            minimum: env::var("MINIMUM")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .expect("Invalid MINIMUM"),
            // Defaults assume the zone does not send mail. Set to empty to disable.
            spf: env::var("SPF").unwrap_or_else(|_| "v=spf1 -all".to_string()),
            dmarc: env::var("DMARC").unwrap_or_else(|_| "v=DMARC1; p=reject;".to_string()),
            version,
            // Both default to 0 (disabled). Set both to a non-zero value to
            // enable: e.g. RATE_LIMIT_REQUESTS=20 RATE_LIMIT_SECONDS=1 allows
            // up to 20 requests per source IP every 1 second.
            rate_limit_seconds: env::var("RATE_LIMIT_SECONDS")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .expect("Invalid RATE_LIMIT_SECONDS"),
            rate_limit_requests: env::var("RATE_LIMIT_REQUESTS")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .expect("Invalid RATE_LIMIT_REQUESTS"),
        }
    }
}

fn parse_ns_names(raw: Option<String>, soa_name: &str) -> Vec<String> {
    let names: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        vec![soa_name.to_string()]
    } else {
        names
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ns_names;

    #[test]
    fn ns_names_default_to_soa() {
        assert_eq!(
            parse_ns_names(None, "ns.example.com"),
            vec!["ns.example.com".to_string()]
        );
        assert_eq!(
            parse_ns_names(Some("  ".into()), "ns.example.com"),
            vec!["ns.example.com".to_string()]
        );
    }

    #[test]
    fn ns_names_parses_csv() {
        assert_eq!(
            parse_ns_names(Some("ns.addr.se, ns1.addr.se".into()), "ns.example.com"),
            vec!["ns.addr.se".to_string(), "ns1.addr.se".to_string()]
        );
    }
}
