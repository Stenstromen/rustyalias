use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub fn interpret_ip(domain: &str) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let parts: Vec<&str> = domain.split('.').collect();
    debug!("Domain parts: {parts:?}");

    for part in &parts {
        if part.len() == 8 {
            if let Ok(ip) = parse_hexadecimal_ip(part) {
                debug!("Parsed hexadecimal IPv4: {ip}");
                return Some((Some(ip), None));
            }
        }
    }

    if parts.len() >= 4 {
        for i in 0..=parts.len() - 4 {
            let potential_ip: String = parts[i..i + 4].join(".");
            if let Ok(ip) = Ipv4Addr::from_str(&potential_ip) {
                debug!("Parsed dotted decimal IPv4: {ip}");
                return Some((Some(ip), None));
            }
        }
    }

    for part in &parts {
        if let Some(ipv6) = parse_hyphenated_ipv6(part) {
            debug!("Parsed hyphenated IPv6: {ipv6}");
            return Some((None, Some(ipv6)));
        }
    }

    for part in &parts {
        if let Some(ip) = parse_hyphenated_ip(part) {
            debug!("Parsed hyphenated IPv4: {ip}");
            return Some((Some(ip), None));
        }
    }

    debug!("Failed to interpret any parts as IP from domain: {domain}");
    None
}

pub fn parse_hyphenated_ipv6(s: &str) -> Option<Ipv6Addr> {
    let s = s.replace("--", "::");
    let s = s.replace('-', ":");
    Ipv6Addr::from_str(&s).ok()
}

pub fn parse_hyphenated_ip(s: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = s.split('-').collect();
    debug!("Hyphenated IP parts: {parts:?}");
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

pub fn parse_hexadecimal_ip(s: &str) -> Result<Ipv4Addr, ()> {
    debug!("Attempting to parse hex IP: {s}");
    if s.len() != 8 {
        return Err(());
    }

    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }

    let mut octets: [u8; 4] = [0u8; 4];
    for i in 0..4 {
        let hex_str = &s[2 * i..2 * i + 2];
        octets[i] = u8::from_str_radix(hex_str, 16).map_err(|_| ())?;
    }

    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dot_notation() {
        let cases = [
            ("10.0.0.1.example.com", "10.0.0.1"),
            ("app.10.8.0.1.example.com", "10.8.0.1"),
            ("customer1.app.10.0.0.1.example.com", "10.0.0.1"),
        ];

        for (input, expected) in cases {
            let result = interpret_ip(input);
            let expected_ip = expected.parse::<Ipv4Addr>().unwrap();
            assert_eq!(result, Some((Some(expected_ip), None)));
        }
    }

    #[test]
    fn test_dash_notation() {
        let cases = [
            ("192-168-1-250.example.com", "192.168.1.250"),
            ("app-116-203-255-68.example.com", "116.203.255.68"),
            ("customer2-app-127-0-0-1.example.com", "127.0.0.1"),
        ];

        for (input, expected) in cases {
            let result = interpret_ip(input);
            let expected_ip = expected.parse::<Ipv4Addr>().unwrap();
            assert_eq!(result, Some((Some(expected_ip), None)));
        }
    }

    #[test]
    fn test_hex_notation() {
        let cases = [
            ("0a000803.example.com", "10.0.8.3"),
            ("app-c0a801fc.example.com", "192.168.1.252"),
            ("customer3-app-7f000101.example.com", "127.0.1.1"),
        ];

        for (input, expected) in cases {
            let result = interpret_ip(input);
            let expected_ip = expected.parse::<Ipv4Addr>().unwrap();
            assert_eq!(result, Some((Some(expected_ip), None)));
        }
    }

    #[test]
    fn test_ipv6_notation() {
        let cases = [
            ("2a04-4e42-200--201.example.com", "2a04:4e42:200::201"),
            (
                "customer4.2a04-4e42-200--201.example.com",
                "2a04:4e42:200::201",
            ),
        ];

        for (input, expected) in cases {
            let result = interpret_ip(input);
            let expected_ip = expected.parse::<Ipv6Addr>().unwrap();
            assert_eq!(result, Some((None, Some(expected_ip))));
        }
    }

    #[test]
    fn test_invalid_inputs() {
        let invalid_cases = [
            "invalid.example.com",
            "256.256.256.256.example.com",
            "not-an-ip.example.com",
            "gggggggg.example.com", // invalid hex
        ];

        for input in invalid_cases {
            let result = interpret_ip(input);
            assert_eq!(result, None);
        }
    }
}
