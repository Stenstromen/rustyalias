use std::env;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct Config {
    pub glue_name: String,
    pub glue_ip: Ipv4Addr,
    pub soa_name: String,
    pub hostmaster: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            glue_name: env::var("GLUE_NAME").unwrap_or_else(|_| "ns.example.com".to_string()),
            glue_ip: env::var("GLUE_IP")
                .unwrap_or_else(|_| "127.0.0.1".to_string())
                .parse()
                .expect("Invalid GLUE_IP"),
            soa_name: env::var("SOA_NAME").unwrap_or_else(|_| "ns.example.com".to_string()),
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
        }
    }
}
