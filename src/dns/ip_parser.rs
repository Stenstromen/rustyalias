use log::debug;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Extract at most one IPv4 and one IPv6 from DNS labels in `domain`.
///
/// Dual-stack hostnames use separate labels for each family, e.g.
/// `127-0-0-1.2a04-4e42-200--201.example.com`.
pub fn interpret_ip(domain: &str) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let parts: Vec<&str> = domain.split('.').collect();
    debug!("Domain parts: {parts:?}");

    let mut ipv4: Option<Ipv4Addr> = None;
    let mut ipv6: Option<Ipv6Addr> = None;

    for part in &parts {
        if ipv4.is_none() {
            if let Some(ip) = parse_label_ipv4(part) {
                debug!("Parsed IPv4 label [{part}]: {ip}");
                ipv4 = Some(ip);
            }
        }
        if ipv6.is_none() {
            if let Some(ip) = parse_hyphenated_ipv6(part) {
                debug!("Parsed IPv6 label [{part}]: {ip}");
                ipv6 = Some(ip);
            }
        }
        if ipv4.is_some() && ipv6.is_some() {
            break;
        }
    }

    if ipv4.is_none() {
        if let Some(ip) = parse_dotted_ipv4(&parts) {
            debug!("Parsed dotted decimal IPv4: {ip}");
            ipv4 = Some(ip);
        }
    }

    if ipv4.is_none() && ipv6.is_none() {
        debug!("Failed to interpret any parts as IP from domain: {domain}");
        return None;
    }

    Some((ipv4, ipv6))
}

fn parse_label_ipv4(label: &str) -> Option<Ipv4Addr> {
    if label.len() == 8 {
        if let Ok(ip) = parse_hexadecimal_ip(label) {
            return Some(ip);
        }
    }
    parse_hyphenated_ip(label)
}

fn parse_dotted_ipv4(parts: &[&str]) -> Option<Ipv4Addr> {
    if parts.len() < 4 {
        return None;
    }
    for i in 0..=parts.len() - 4 {
        let potential_ip = parts[i..i + 4].join(".");
        if let Ok(ip) = Ipv4Addr::from_str(&potential_ip) {
            return Some(ip);
        }
    }
    None
}

pub fn parse_hyphenated_ipv6(s: &str) -> Option<Ipv6Addr> {
    // Require at least one hyphen so plain labels are not treated as IPv6.
    if !s.contains('-') {
        return None;
    }
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
    fn test_dual_stack_two_labels() {
        let v4: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let v6: Ipv6Addr = "2a04:4e42:200::201".parse().unwrap();

        let cases = [
            "127-0-0-1.2a04-4e42-200--201.example.com",
            "2a04-4e42-200--201.127-0-0-1.example.com",
            "app.127-0-0-1.2a04-4e42-200--201.example.com",
            "app.2a04-4e42-200--201.127-0-0-1.example.com",
            "7f000001.2a04-4e42-200--201.example.com",
            "2a04-4e42-200--201.7f000001.example.com",
        ];

        for input in cases {
            let result = interpret_ip(input);
            assert_eq!(
                result,
                Some((Some(v4), Some(v6))),
                "dual-stack parse failed for {input}"
            );
        }

        let dotted = interpret_ip("10.0.0.1.2a04-4e42-200--201.example.com");
        assert_eq!(dotted, Some((Some("10.0.0.1".parse().unwrap()), Some(v6))));
    }

    #[test]
    fn test_concatenated_label_is_not_dual_stack() {
        // Single label with both encodings jammed together is ambiguous IPv6,
        // not the supported dual-stack form.
        let result = interpret_ip("2a04-4e42-200--201-127-0-0-1.example.com");
        assert!(
            result.is_none() || matches!(result, Some((None, Some(_))) | Some((Some(_), None))),
            "concatenated label must not yield both families: {result:?}"
        );
        if let Some((v4, v6)) = result {
            assert!(
                v4.is_none() || v6.is_none(),
                "expected at most one family, got v4={v4:?} v6={v6:?}"
            );
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
