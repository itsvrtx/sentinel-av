use std::net::{IpAddr, Ipv4Addr};

const SUSPICIOUS_DOMAIN_SUFFIXES: &[&str] = &[
    ".duckdns.org",
    ".ngrok.io",
    ".ngrok-free.app",
    ".ddns.net",
    ".no-ip.biz",
    ".top",
    ".xyz",
    ".onion",
];

const KNOWN_C2_DOMAINS: &[&str] = &[
    "evil-c2.net",
    "c2-beacon.internal-fake.com",
    "malicious-payload-drop.org",
    "stealer-c2-vault.com",
];

/// Checks if a domain matches known C2 infrastructure or heavily abused dynamic DNS services.
pub fn is_malicious_domain(domain: &str) -> bool {
    let lower = domain.trim().to_lowercase();
    if KNOWN_C2_DOMAINS.iter().any(|&c2| lower == c2) {
        return true;
    }
    SUSPICIOUS_DOMAIN_SUFFIXES.iter().any(|&suffix| lower.ends_with(suffix))
}

/// Sinkholes DNS query response to 0.0.0.0 if domain is recognized as malicious C2.
pub fn sinkhole_dns_query(domain: &str) -> Option<IpAddr> {
    if is_malicious_domain(domain) {
        Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_sinkholing() {
        assert_eq!(
            sinkhole_dns_query("payload-stage.duckdns.org"),
            Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        );
        assert_eq!(
            sinkhole_dns_query("evil-c2.net"),
            Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        );
        assert_eq!(
            sinkhole_dns_query("c2-beacon.internal-fake.com"),
            Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        );

        // Safe domains allowed
        assert_eq!(sinkhole_dns_query("google.com"), None);
        assert_eq!(sinkhole_dns_query("crates.io"), None);
    }
}
