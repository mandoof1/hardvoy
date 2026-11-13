//! WebRTC ICE candidate auditing — the leak that de-anonymises an operator
//! even when every HTTP request went through Tor.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub foundation: String,
    pub component: String,
    pub transport: String,
    pub priority: u64,
    pub address: String,
    pub port: u16,
    pub kind: String, // host | srflx | prflx | relay
    pub address_class: String,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WebRtcAudit {
    pub present: bool,
    pub candidate_count: usize,
    pub mdns_only: bool,
    pub leaked_private: Vec<String>,
    pub leaked_public: Vec<String>,
    pub leaked_ipv6: Vec<String>,
    pub embedded_public_from_ipv6: Vec<String>,
    pub reflexive_public: Vec<String>,
    pub severity: String,
    pub findings: Vec<String>,
    pub candidates: Vec<Candidate>,
}

/// Classify an address string. Never guesses: anything unparseable is reported
/// as `unparsed`.
pub fn classify_address(a: &str) -> String {
    if a.ends_with(".local") {
        return "mdns".to_string();
    }
    match a.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => classify_v4(v4),
        Ok(IpAddr::V6(v6)) => classify_v6(v6),
        Err(_) => "unparsed".to_string(),
    }
}

fn classify_v4(a: Ipv4Addr) -> String {
    let o = a.octets();
    match o {
        _ if a.is_loopback() => "loopback",
        _ if a.is_link_local() => "link-local",
        _ if o[0] == 10 => "private(10/8)",
        _ if o[0] == 172 && (16..=31).contains(&o[1]) => "private(172.16/12)",
        _ if o[0] == 192 && o[1] == 168 => "private(192.168/16)",
        _ if o[0] == 100 && (64..=127).contains(&o[1]) => "cgnat(100.64/10)",
        _ if a.is_multicast() => "multicast",
        _ if a.is_unspecified() => "unspecified",
        _ => "public",
    }
    .to_string()
}

fn classify_v6(a: Ipv6Addr) -> String {
    let seg = a.segments();
    if a.is_loopback() {
        return "loopback".to_string();
    }
    if seg[0] & 0xffc0 == 0xfe80 {
        return "link-local".to_string();
    }
    if seg[0] & 0xfe00 == 0xfc00 {
        return "ula(fc00::/7)".to_string();
    }
    if seg[0] == 0x2001 && seg[1] == 0 {
        return "teredo(2001::/32)".to_string();
    }
    if seg[0] == 0x2002 {
        return "6to4(2002::/16)".to_string();
    }
    if a.is_multicast() {
        return "multicast".to_string();
    }
    if a.is_unspecified() {
        return "unspecified".to_string();
    }
    "public".to_string()
}

/// Teredo (2001::/32) and 6to4 (2002::/16) hide a public IPv4 inside the IPv6
/// address. Surfacing that is the whole point of auditing IPv6 candidates.
pub fn embedded_v4(a: &str) -> Option<Ipv4Addr> {
    let v6 = a.parse::<Ipv6Addr>().ok()?;
    let s = v6.segments();
    if s[0] == 0x2001 && s[1] == 0 {
        let ip = Ipv4Addr::new(
            (s[4] >> 8) as u8,
            (s[4] & 0xff) as u8,
            (s[5] >> 8) as u8,
            (s[5] & 0xff) as u8,
        );
        return Some(ip);
    }
    if s[0] == 0x2002 {
        let ip = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        return Some(ip);
    }
    None
}

/// Parse one `a=candidate:` / `candidate:` line.
pub fn parse_candidate(line: &str) -> Option<Candidate> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let body = line.strip_prefix("a=").unwrap_or(line);
    let body = body.strip_prefix("candidate:").unwrap_or(body);
    let toks: Vec<&str> = body.split_whitespace().collect();
    if toks.len() < 7 {
        return None;
    }
    let typ_idx = toks.iter().position(|t| *t == "typ")?;
    if typ_idx + 1 >= toks.len() || typ_idx < 6 {
        return None;
    }
    let address = toks[4].to_string();
    let port = toks[5].parse::<u16>().unwrap_or(0);
    Some(Candidate {
        foundation: toks[0].to_string(),
        component: toks[1].to_string(),
        transport: toks[2].to_uppercase(),
        priority: toks[3].parse().unwrap_or(0),
        address,
        port,
        kind: toks[typ_idx + 1].to_lowercase(),
        address_class: String::new(),
        raw: line.to_string(),
    })
}

/// Audit a set of candidate strings.
///
/// `anonymous_egress` is true when the HTTP path is Tor/VPN/proxy: leaking a
/// LAN address or a routable IPv6 through WebRTC is then a *complete* cover
/// failure, which is why severity is raised in that case.
pub fn audit(lines: &[String], anonymous_egress: bool) -> WebRtcAudit {
    let mut out = WebRtcAudit::default();
    let mut cands = Vec::new();
    for l in lines {
        if let Some(mut c) = parse_candidate(l) {
            c.address_class = classify_address(&c.address);
            cands.push(c);
        }
    }
    out.candidate_count = cands.len();
    out.present = !cands.is_empty();
    out.candidates = cands.clone();

    let mdns = cands.iter().filter(|c| c.address_class == "mdns").count();
    out.mdns_only = !cands.is_empty() && mdns == cands.len();

    for c in &cands {
        let cls = c.address_class.as_str();
        let is_host = c.kind == "host";
        match cls {
            "private(10/8)"
            | "private(172.16/12)"
            | "private(192.168/16)"
            | "cgnat(100.64/10)"
            | "ula(fc00::/7)" => {
                if !out.leaked_private.contains(&c.address) {
                    out.leaked_private.push(c.address.clone());
                }
                if !is_host {
                    out.findings.push(format!(
                        "private address {} published as a {} candidate (usually it is only a host candidate)",
                        c.address, c.kind
                    ));
                }
            }
            "link-local" => {
                if !out.leaked_private.contains(&c.address) {
                    out.leaked_private.push(c.address.clone());
                }
            }
            "public" => {
                if c.kind == "srflx" || c.kind == "prflx" {
                    if !out.reflexive_public.contains(&c.address) {
                        out.reflexive_public.push(c.address.clone());
                    }
                } else if !out.leaked_public.contains(&c.address) {
                    out.leaked_public.push(c.address.clone());
                }
                if c.address.contains(':') && !out.leaked_ipv6.contains(&c.address) {
                    out.leaked_ipv6.push(c.address.clone());
                }
            }
            "teredo(2001::/32)" | "6to4(2002::/16)" => {
                if !out.leaked_ipv6.contains(&c.address) {
                    out.leaked_ipv6.push(c.address.clone());
                }
                if let Some(v4) = embedded_v4(&c.address) {
                    let s = v4.to_string();
                    if !out.embedded_public_from_ipv6.contains(&s) {
                        out.embedded_public_from_ipv6.push(s);
                    }
                }
            }
            "loopback" => {}
            _ => {}
        }
    }

    // Severity is a ladder, and each rule may only raise it: a public address
    // plus a private one is still a high finding, not a medium one.
    fn rank(s: &str) -> u8 {
        match s {
            "none" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            _ => 4,
        }
    }
    let mut sev = "none";
    let mut raise = |sev: &mut &str, to: &'static str, why: String| {
        if rank(to) >= rank(sev) {
            *sev = to;
        }
        out.findings.push(why);
    };

    if !out.reflexive_public.is_empty() {
        raise(
            &mut sev,
            "high",
            format!(
                "STUN reflexive candidate exposes the public address {}",
                out.reflexive_public.join(", ")
            ),
        );
    }
    // one list, deduplicated: a public IPv6 lands in both vectors
    let mut routable: Vec<String> = Vec::new();
    for a in out
        .leaked_public
        .iter()
        .chain(out.leaked_ipv6.iter())
        .chain(out.embedded_public_from_ipv6.iter())
    {
        if !routable.contains(a) {
            routable.push(a.clone());
        }
    }
    if !routable.is_empty() {
        raise(
            &mut sev,
            "high",
            format!(
                "routable address published in the SDP: {}",
                routable.join(", ")
            ),
        );
    }
    if !out.leaked_private.is_empty() {
        // on an anonymous egress a local address also defeats the path itself
        raise(
            &mut sev,
            if anonymous_egress { "high" } else { "medium" },
            format!(
                "local interface address published in the SDP: {}",
                out.leaked_private.join(", ")
            ),
        );
    }
    if out.mdns_only && out.leaked_private.is_empty() && out.leaked_public.is_empty() {
        raise(
            &mut sev,
            "none",
            "host candidates are mDNS names only: no numeric interface address left the browser"
                .to_string(),
        );
    }
    if out.candidate_count == 0 {
        out.findings
            .push("no ICE candidates were gathered at all".to_string());
    }
    out.severity = sev.to_string();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREFOX_LEAK: &str = "candidate:0 1 UDP 2122187007 192.168.8.88 49345 typ host";
    const FIREFOX_MDNS: &str =
        "candidate:0 1 UDP 2122187007 6b2f0c1e-9a11-4c2a-9a1b-1f2e3d4c5b6a.local 49345 typ host";
    const CHROME_SRFLX: &str =
        "candidate:842163049 1 udp 1677729535 203.0.113.7 34789 typ srflx raddr 192.168.1.10 rport 51234";

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_firefox_candidate() {
        let c = parse_candidate(FIREFOX_LEAK).expect("parse");
        assert_eq!(c.address, "192.168.8.88");
        assert_eq!(c.port, 49345);
        assert_eq!(c.kind, "host");
        assert_eq!(c.transport, "UDP");
        assert_eq!(c.priority, 2122187007);
    }

    #[test]
    fn parses_a_candidate_prefixed_line() {
        let c = parse_candidate(&format!("a={FIREFOX_LEAK}")).expect("parse a=");
        assert_eq!(c.address, "192.168.8.88");
    }

    #[test]
    fn classification() {
        assert_eq!(classify_address("192.168.8.88"), "private(192.168/16)");
        assert_eq!(classify_address("10.1.2.3"), "private(10/8)");
        assert_eq!(classify_address("172.16.0.1"), "private(172.16/12)");
        assert_eq!(classify_address("172.32.0.1"), "public");
        assert_eq!(classify_address("100.64.0.1"), "cgnat(100.64/10)");
        assert_eq!(classify_address("127.0.0.1"), "loopback");
        assert_eq!(classify_address("169.254.5.5"), "link-local");
        assert_eq!(classify_address("203.0.113.7"), "public");
        assert_eq!(classify_address("fe80::1"), "link-local");
        assert_eq!(classify_address("fd12::1"), "ula(fc00::/7)");
        assert_eq!(classify_address("2001:db8::1"), "public");
        assert_eq!(classify_address("2002:c000:203::1"), "6to4(2002::/16)");
        assert_eq!(
            classify_address("6b2f0c1e-9a11-4c2a-9a1b-1f2e3d4c5b6a.local"),
            "mdns"
        );
        assert_eq!(classify_address("not-an-ip"), "unparsed");
    }

    #[test]
    fn embedded_public_ipv4_from_ipv6() {
        // 2002:c000:0203:: == 192.0.2.3 via 6to4
        assert_eq!(
            embedded_v4("2002:c000:0203::1").map(|x| x.to_string()),
            Some("192.0.2.3".to_string())
        );
        // Teredo: client IPv4 in the low 32 bits (obfuscated), hardvoy reports
        // the de-obfuscated value it can see, which is the raw pair.
        assert!(
            embedded_v4("2001:0000:4136:e378:8000:63bf:3fff:fdd2").map(|x| x.to_string())
                == Some("128.0.99.191".to_string())
        );
        assert_eq!(embedded_v4("2001:db8::1"), None);
    }

    #[test]
    fn leaky_run_is_high_when_egress_is_anonymous() {
        let a = audit(&v(&[FIREFOX_LEAK, &format!("a={FIREFOX_LEAK}")]), true);
        assert_eq!(a.severity, "high");
        assert!(a.leaked_private.iter().any(|x| x == "192.168.8.88"));
        assert!(a
            .findings
            .iter()
            .any(|f| f.contains("local interface address")));
    }

    #[test]
    fn same_leak_is_medium_on_a_plain_connection() {
        let a = audit(&v(&[FIREFOX_LEAK]), false);
        assert_eq!(a.severity, "medium");
    }

    #[test]
    fn mdns_only_is_not_a_leak() {
        let a = audit(&v(&[FIREFOX_MDNS, FIREFOX_MDNS]), true);
        assert!(a.mdns_only);
        assert_eq!(a.severity, "none");
        assert!(a.leaked_private.is_empty());
        assert!(a.findings.iter().any(|f| f.contains("mDNS")));
    }

    #[test]
    fn public_and_private_together_stay_high_on_a_plain_egress() {
        // regression: the private-address rule used to overwrite a high
        // verdict with medium, which hid the more serious leak
        let lines = vec![
            "candidate:0 1 UDP 2122187007 192.168.8.88 49345 typ host".to_string(),
            "candidate:1 1 UDP 1694498815 2001:8f8:2d87:5e9f:629d:1bfc:686b:2 51234 typ host"
                .to_string(),
        ];
        let a = audit(&lines, false);
        assert_eq!(a.severity, "high");
        assert_eq!(a.leaked_private, vec!["192.168.8.88"]);
        assert_eq!(a.leaked_public.len(), 1);
        let routable: Vec<String> = a
            .findings
            .iter()
            .filter(|f| f.starts_with("routable address"))
            .flat_map(|f| f.split_whitespace().skip(4).map(String::from))
            .collect();
        assert_eq!(
            routable
                .iter()
                .filter(|x| x.starts_with("2001:8f8"))
                .count(),
            1,
            "the same address must not be listed twice: {routable:?}"
        );
    }

    #[test]
    fn private_only_leak_is_medium_on_plain_and_high_on_tor() {
        let lines = vec!["candidate:0 1 UDP 2122187007 10.0.0.7 9 typ host".to_string()];
        assert_eq!(audit(&lines, false).severity, "medium");
        assert_eq!(audit(&lines, true).severity, "high");
    }

    #[test]
    fn reflexive_public_is_high() {
        let a = audit(&v(&[CHROME_SRFLX]), true);
        assert_eq!(a.severity, "high");
        assert_eq!(a.reflexive_public, vec!["203.0.113.7".to_string()]);
    }

    #[test]
    fn teredo_embedded_v4_is_surfaced() {
        let l = "candidate:0 1 UDP 1 2002:c000:0203::5 9 typ host";
        let a = audit(&v(&[l]), true);
        assert_eq!(a.embedded_public_from_ipv6, vec!["192.0.2.3".to_string()]);
        assert_eq!(a.severity, "high");
    }

    #[test]
    fn empty_gathering_is_reported() {
        let a = audit(&[], false);
        assert!(!a.present);
        assert!(a.findings.iter().any(|f| f.contains("no ICE candidates")));
    }

    #[test]
    fn garbage_lines_are_ignored_not_panicking() {
        let a = audit(&v(&["", "garbage", "candidate:1 2", FIREFOX_LEAK]), false);
        assert_eq!(a.candidate_count, 1);
    }
}
