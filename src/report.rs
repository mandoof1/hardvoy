//! The report model and the offline HTML renderer.
//!
//! A scan produces one `Report`. It is written as JSON (machine-readable, part
//! of the evidence) and as a self-contained HTML file that renders with no
//! network, no fonts, and no scripts — an auditor can open it on an air-gapped
//! machine and see the same thing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "hardvoy/1";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub id: String,
    pub generated_at: String,
    pub tool: ToolInfo,
    pub host: HostInfo,
    pub lab: LabInfo,
    pub config: ConfigView,
    pub egresses: Vec<EgressView>,
    pub findings: Vec<Finding>,
    pub correlation: Correlation,
    pub circuits: Vec<CircuitView>,
    pub timings: BTreeMap<String, f64>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub environment: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub arch: String,
    pub cpus: usize,
    pub memtotal_kb: u64,
    pub timezone: String,
    pub locale: String,
    pub display: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabInfo {
    pub http: String,
    pub tls: String,
    pub ssh: String,
    pub mode: String,
    pub probe_js_sha256: String,
    pub planted: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigView {
    pub egresses: Vec<String>,
    pub circuits: usize,
    pub profile: String,
    pub browser: String,
    pub mode: String,
    pub probe_timeout_secs: u64,
    pub stability_runs: usize,
    pub stability_profiles: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressView {
    pub name: String,
    pub kind: String,
    pub proxy: String,
    pub onion: Option<String>,
    /// The Tor circuit this path was measured over, when a circuit was pinned.
    pub circuit: Option<CircuitView>,
    pub url: String,
    pub browser: Option<BrowserView>,
    pub webrtc: Option<crate::webrtc::WebRtcAudit>,
    pub http: Vec<HttpView>,
    pub tls: Vec<TlsView>,
    pub ssh: Option<SshView>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrowserView {
    pub profile: String,
    pub user_agent: Option<String>,
    pub groups: BTreeMap<String, String>,
    pub payload: serde_json::Value,
    pub collect_ms: f64,
    pub page_load_ms: f64,
    pub screenshot: Option<String>,
    pub session_caps: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpView {
    pub seen_by: String,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub header_order: Vec<String>,
    pub order_hash: String,
    pub content_hash: String,
    pub header_count: usize,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub client_hints: Vec<String>,
    pub sec_fetch: Vec<String>,
    pub proxy_injected: Vec<String>,
    pub raw_head: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsView {
    pub variant: String,
    pub via: String,
    pub ours: crate::tlsf::TlsSummary,
    pub lab_seen: Option<crate::tlsf::TlsSummary>,
    pub forwarder_seen: Option<crate::tlsf::TlsSummary>,
    pub lab_matches_ours: bool,
    pub forwarder_matches_ours: bool,
    pub bytes_sent: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshView {
    pub via: String,
    pub our_hassh: String,
    pub their_hassh: String,
    pub their_banner: String,
    pub our_kex: Vec<String>,
    pub their_kex: Vec<String>,
    pub lab_confirmed_hassh: Option<String>,
    pub lab_confirms: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CircuitView {
    pub label: String,
    pub onion: String,
    pub purpose: String,
    pub state: String,
    pub path_fingerprints: Vec<String>,
    pub path_nicks: Vec<String>,
    pub exit_fingerprint: Option<String>,
    pub probe_status: u16,
    pub raw: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub egress: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Correlation {
    /// Fingerprints that stay identical across every egress: what an observer
    /// on both paths would use to link them.
    pub shared: Vec<(String, String)>,
    /// Fingerprints that differ between egresses.
    pub divergent: Vec<(String, Vec<String>)>,
    pub risk: String,
    pub explanation: String,
}

/// Which fingerprint names the report compares across egresses.
pub const COMPARED: [&str; 17] = [
    "env",
    "locale",
    "clock",
    "canvas",
    "webgl",
    "audio",
    "fonts",
    "geometry",
    "storage",
    "media",
    "webrtc",
    "user-agent",
    "http-header-order",
    "http-content",
    "tls-ja3",
    "tls-ja4",
    "ssh-hassh",
];

pub fn fingerprint_of(e: &EgressView, name: &str) -> Option<String> {
    match name {
        "user-agent" => e
            .browser
            .as_ref()
            .and_then(|b| b.user_agent.clone())
            .map(|ua| crate::util::short_hash(&ua)),
        "http-header-order" => e.http.first().map(|h| h.order_hash.clone()),
        "http-content" => e.http.first().map(|h| h.content_hash.clone()),
        "tls-ja3" => e.tls.first().map(|t| t.ours.ja3.clone()),
        "tls-ja4" => e.tls.first().map(|t| t.ours.ja4.clone()),
        "ssh-hassh" => e.ssh.as_ref().map(|s| s.our_hassh.clone()),
        other => e
            .browser
            .as_ref()
            .and_then(|b| b.groups.get(other))
            .cloned(),
    }
}

/// Compare fingerprints across egresses: what an observer on more than one
/// path can use to decide "same operator".
pub fn correlate(egresses: &[EgressView]) -> Correlation {
    let mut c = Correlation {
        risk: "unknown".into(),
        ..Default::default()
    };
    if egresses.len() < 2 {
        c.explanation = "one egress only: nothing to correlate".into();
        c.risk = "not-measured".into();
        return c;
    }
    let mut same = 0usize;
    let mut diff = 0usize;
    for name in COMPARED {
        let vals: Vec<Option<String>> = egresses.iter().map(|e| fingerprint_of(e, name)).collect();
        let present: Vec<String> = vals.iter().flatten().cloned().collect();
        if present.len() < egresses.len() {
            continue; // not measured on every path: no claim either way
        }
        let all_equal = present.windows(2).all(|w| w[0] == w[1]);
        if all_equal {
            same += 1;
            c.shared.push((name.to_string(), present[0].clone()));
        } else {
            diff += 1;
            c.divergent.push((name.to_string(), present));
        }
    }
    let total = same + diff;
    c.explanation = format!(
        "{same} of {total} measured fingerprints are identical on every egress path, \
         {diff} differ. An observer able to watch both paths can link the sessions by \
         the identical ones, because Tor changes the network path but not what the \
         browser or the TLS stack advertises."
    );
    c.risk = if total == 0 {
        "not-measured".into()
    } else if same as f64 / total as f64 >= 0.6 {
        "high".into()
    } else if same > 0 {
        "medium".into()
    } else {
        "low".into()
    };
    c
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

const CSS: &str = r#"
:root{color-scheme:light}
*{box-sizing:border-box}
body{font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:0;background:#0f1115;color:#e6e6e6}
main{max-width:1180px;margin:0 auto;padding:28px 22px 80px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:34px 0 10px;border-bottom:1px solid #2b2f38;padding-bottom:6px}
h3{font-size:15px;margin:20px 0 8px;color:#9ecbff}
a{color:#8ab4f8}
.sub{color:#9aa0a6;margin-bottom:18px}
table{border-collapse:collapse;width:100%;margin:8px 0 14px;background:#151821}
th,td{border:1px solid #2b2f38;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#1c2130;font-weight:600}
.same{background:#123320;color:#7ee2a0}
.diff{background:#3a1d1d;color:#ffb3b3}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.critical{background:#5c1a1a;color:#ffb3b3}.high{background:#4a2410;color:#ffbf80}
.medium{background:#3d3a12;color:#f2e08a}.low{background:#1d3348;color:#a8d1ff}
.info{background:#22283a;color:#b9c4e0}
.hash{font-size:12px;color:#c9c9c9}
pre{background:#11141b;border:1px solid #2b2f38;padding:10px;overflow:auto;white-space:pre-wrap;margin:6px 0}
details{margin:8px 0}
summary{cursor:pointer;color:#9ecbff}
.kv{display:grid;grid-template-columns:220px 1fr;gap:2px 10px;margin:6px 0}
.kv div{padding:2px 0}
.ok{color:#7ee2a0}.no{color:#ffb3b3}
footer{margin-top:40px;color:#9aa0a6;font-size:12px}
"#;

/// Render the whole report as one self-contained HTML page.
pub fn html(r: &Report) -> String {
    let mut o = String::new();
    o.push_str("<!doctype html>\n<html lang=en><head><meta charset=utf-8>\n");
    o.push_str("<title>hardvoy report ");
    o.push_str(&esc(&r.id));
    o.push_str("</title><style>");
    o.push_str(CSS);
    o.push_str("</style></head><body><main>\n");

    o.push_str("<h1>hardvoy — operator leak audit</h1>\n");
    o.push_str(&format!(
        "<div class=sub>report {} &middot; schema {} &middot; generated {} &middot; {} v{}</div>\n",
        esc(&r.id),
        SCHEMA,
        esc(&r.generated_at),
        esc(&r.tool.name),
        esc(&r.tool.version)
    ));

    // summary card
    let crit = r
        .findings
        .iter()
        .filter(|f| f.severity == "critical")
        .count();
    let high = r.findings.iter().filter(|f| f.severity == "high").count();
    let med = r.findings.iter().filter(|f| f.severity == "medium").count();
    o.push_str("<h2>Summary</h2>\n<div class=kv>\n");
    for (k, v) in [
        ("Egress paths", &r.egresses.len().to_string()),
        ("Circuits observed", &r.circuits.len().to_string()),
        ("Findings", &r.findings.len().to_string()),
        ("Critical", &crit.to_string()),
        ("High", &high.to_string()),
        ("Medium", &med.to_string()),
        ("Correlation risk", &r.correlation.risk),
    ] {
        o.push_str(&format!("<div>{k}</div><div>{}</div>\n", esc(v)));
    }
    o.push_str("</div>\n");

    // findings
    o.push_str("<h2>Findings</h2>\n");
    if r.findings.is_empty() {
        o.push_str("<div class=sub>No findings recorded.</div>\n");
    } else {
        o.push_str("<table><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Egress</th><th>Evidence</th></tr>\n");
        for f in &r.findings {
            o.push_str(&format!(
                "<tr><td><span class=\"badge {}\">{}</span></td><td>{}</td><td><b>{}</b><br>{}<br><i>{}: {}</i></td><td>{}</td><td class=hash>{}</td></tr>\n",
                esc(&f.severity),
                esc(&f.severity),
                esc(&f.id),
                esc(&f.title),
                esc(&f.detail),
                "Recommendation",
                esc(&f.recommendation),
                esc(&f.egress),
                f.evidence
                    .iter()
                    .map(|e| esc(e))
                    .collect::<Vec<_>>()
                    .join("<br>")
            ));
        }
        o.push_str("</table>\n");
    }

    // correlation matrix
    o.push_str("<h2>Fingerprint divergence across egresses</h2>\n");
    o.push_str(&format!(
        "<div class=sub>{}</div>\n",
        esc(&r.correlation.explanation)
    ));
    let names: Vec<String> = r.egresses.iter().map(|e| e.name.clone()).collect();
    o.push_str("<table><tr><th>Fingerprint</th>");
    for n in &names {
        o.push_str(&format!("<th>{}</th>", esc(n)));
    }
    o.push_str("<th>Verdict</th></tr>\n");
    for name in COMPARED {
        o.push_str(&format!("<tr><td>{}</td>", esc(name)));
        let vals: Vec<Option<String>> =
            r.egresses.iter().map(|e| fingerprint_of(e, name)).collect();
        let present: Vec<String> = vals.iter().flatten().cloned().collect();
        let mut cls = String::new();
        let mut verdict = "not measured on every path".to_string();
        if present.len() == r.egresses.len() && !present.is_empty() {
            let all_equal = present.windows(2).all(|w| w[0] == w[1]);
            cls = if all_equal {
                "same".to_string()
            } else {
                "diff".to_string()
            };
            verdict = if all_equal {
                "identical on all paths — usable to correlate"
            } else {
                "differs per path"
            }
            .to_string();
        }
        for v in &vals {
            match v {
                Some(h) => o.push_str(&format!(
                    "<td class=\"{cls}\"><span class=hash>{}</span></td>",
                    esc(h)
                )),
                None => o.push_str("<td><span class=sub>—</span></td>"),
            }
        }
        o.push_str(&format!("<td>{verdict}</td></tr>\n"));
    }
    o.push_str("</table>\n");

    // per-egress detail
    o.push_str("<h2>Egress paths</h2>\n");
    for e in &r.egresses {
        o.push_str(&format!("<h3>{}</h3>\n", esc(&e.name)));
        o.push_str("<div class=kv>\n");
        for (k, v) in [
            ("Kind", &e.kind),
            ("Proxy", &e.proxy),
            ("URL fetched", &e.url),
        ] {
            o.push_str(&format!("<div>{k}</div><div>{}</div>\n", esc(v)));
        }
        if let Some(on) = &e.onion {
            o.push_str(&format!(
                "<div>Hidden service</div><div>{}</div>\n",
                esc(on)
            ));
        }
        o.push_str("</div>\n");
        if !e.errors.is_empty() {
            o.push_str("<pre>");
            for x in &e.errors {
                o.push_str(&esc(x));
                o.push('\n');
            }
            o.push_str("</pre>\n");
        }

        if let Some(b) = &e.browser {
            o.push_str("<h4>Browser probe (Firefox via WebDriver)</h4>\n<div class=kv>\n");
            o.push_str(&format!(
                "<div>Profile</div><div>{}</div>\n<div>Collect time</div><div>{:.1} ms</div>\n<div>Page load</div><div>{:.1} ms</div>\n<div>User-Agent</div><div>{}</div>\n",
                esc(&b.profile),
                b.collect_ms,
                b.page_load_ms,
                esc(b.user_agent.as_deref().unwrap_or("?"))
            ));
            o.push_str("</div>\n<table><tr><th>Probe group</th><th>SHA-256 (first 16)</th></tr>\n");
            for (g, h) in &b.groups {
                o.push_str(&format!(
                    "<tr><td>{}</td><td class=hash>{}</td></tr>\n",
                    esc(g),
                    esc(h)
                ));
            }
            o.push_str("</table>\n");
            if let Some(sc) = &b.screenshot {
                o.push_str(&format!("<div class=sub>Screenshot: {}</div>\n", esc(sc)));
            }
            o.push_str(
                "<details><summary>probe payload (JSON as the page posted it)</summary><pre>",
            );
            o.push_str(&esc(
                &serde_json::to_string_pretty(&b.payload).unwrap_or_default()
            ));
            o.push_str("</pre></details>\n");
        }

        if let Some(w) = &e.webrtc {
            o.push_str("<h4>WebRTC ICE audit</h4>\n<div class=kv>\n");
            o.push_str(&format!(
                "<div>Severity</div><div><span class=\"badge {}\">{}</span></div>\n<div>Candidates</div><div>{}</div>\n<div>mDNS only</div><div>{}</div>\n<div>Private addresses leaked</div><div>{}</div>\n<div>Public addresses leaked</div><div>{}</div>\n",
                esc(&w.severity),
                esc(&w.severity),
                w.candidate_count,
                w.mdns_only,
                esc(&w.leaked_private.join(", ")),
                esc(&w.leaked_public.join(", "))
            ));
            o.push_str("</div>\n<table><tr><th>Raw candidate</th><th>Address</th><th>Class</th><th>Type</th></tr>\n");
            for c in &w.candidates {
                o.push_str(&format!(
                    "<tr><td class=hash>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    esc(&c.raw),
                    esc(&c.address),
                    esc(&c.address_class),
                    esc(&c.kind)
                ));
            }
            o.push_str("</table>\n");
        }

        if !e.http.is_empty() {
            o.push_str("<h4>HTTP request as the lab saw it</h4>\n<table><tr><th>Seen by</th><th>Header order</th><th>order hash</th><th>content hash</th></tr>\n");
            for h in &e.http {
                o.push_str(&format!(
                    "<tr><td>{}</td><td class=hash>{}</td><td class=hash>{}</td><td class=hash>{}</td></tr>\n",
                    esc(&h.seen_by),
                    esc(&h.header_order.join(", ")),
                    esc(&h.order_hash),
                    esc(&h.content_hash)
                ));
            }
            o.push_str("</table>\n");
            for h in &e.http {
                o.push_str(&format!(
                    "<details><summary>{} request line + headers</summary><pre>{}</pre></details>\n",
                    esc(&h.seen_by),
                    esc(&h.raw_head)
                ));
            }
        }

        if !e.tls.is_empty() {
            o.push_str("<h4>TLS ClientHello fingerprints</h4>\n<table><tr><th>Variant</th><th>Via</th><th>JA3</th><th>JA4</th><th>GREASE</th><th>bytes</th><th>lab agrees</th><th>forwarder agrees</th></tr>\n");
            for t in &e.tls {
                o.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td class=hash>{}</td><td class=hash>{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td class=\"{}\">{}</td></tr>\n",
                    esc(&t.variant),
                    esc(&t.via),
                    esc(&t.ours.ja3),
                    esc(&t.ours.ja4),
                    t.ours.grease_present,
                    t.bytes_sent,
                    if t.lab_matches_ours { "same" } else { "diff" },
                    if t.lab_matches_ours { "yes" } else { "NO" },
                    if t.forwarder_matches_ours { "same" } else { "diff" },
                    if t.forwarder_matches_ours { "yes" } else { "NO" }
                ));
            }
            o.push_str("</table>\n");
            for t in &e.tls {
                o.push_str(&format!(
                    "<details><summary>{} hello detail</summary><pre>{}</pre><pre>{}</pre></details>\n",
                    esc(&t.variant),
                    esc(&t.ours.ja3_string),
                    esc(&t.ours.ja4_raw)
                ));
            }
        }

        if let Some(s) = &e.ssh {
            o.push_str("<h4>SSH KEXINIT (HASSH)</h4>\n<div class=kv>\n");
            o.push_str(&format!(
                "<div>Our HASSH</div><div class=hash>{}</div>\n<div>Their HASSH</div><div class=hash>{}</div>\n<div>Banner</div><div>{}</div>\n<div>Lab confirms our HASSH</div><div class=\"{}\">{}</div>\n",
                esc(&s.our_hassh),
                esc(&s.their_hassh),
                esc(&s.their_banner),
                if s.lab_confirms { "ok" } else { "no" },
                s.lab_confirms
            ));
            o.push_str("</div>\n");
            o.push_str(&format!(
                "<details><summary>kexinit algorithm lists</summary><pre>ours: {}\ntheirs: {}</pre></details>\n",
                esc(&s.our_kex.join(",")),
                esc(&s.their_kex.join(","))
            ));
        }
    }

    // circuits
    o.push_str("<h2>Tor circuits</h2>\n");
    if r.circuits.is_empty() {
        o.push_str("<div class=sub>No Tor circuit evidence in this scan.</div>\n");
    } else {
        o.push_str("<table><tr><th>Label</th><th>Purpose</th><th>State</th><th>Path (relay fingerprints)</th><th>Last hop</th><th>Probe</th></tr>\n");
        for c in &r.circuits {
            o.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=hash>{}</td><td class=hash>{}</td><td>{}</td></tr>\n",
                esc(&c.label),
                esc(&c.purpose),
                esc(&c.state),
                esc(&c.path_fingerprints.join(" -> ")),
                esc(c.exit_fingerprint.as_deref().unwrap_or("?")),
                c.probe_status
            ));
        }
        o.push_str("</table>\n");
    }

    // host + config + environment
    o.push_str("<h2>Host under audit</h2>\n<div class=kv>\n");
    for (k, v) in [
        ("Hostname", &r.host.hostname),
        ("Kernel", &r.host.kernel),
        ("OS", &r.host.os),
        ("Arch", &r.host.arch),
        ("CPUs", &r.host.cpus.to_string()),
        ("Memory kB", &r.host.memtotal_kb.to_string()),
        ("Timezone", &r.host.timezone),
        ("Locale", &r.host.locale),
        ("Display", &r.host.display),
    ] {
        o.push_str(&format!("<div>{k}</div><div>{}</div>\n", esc(v)));
    }
    o.push_str("</div>\n");

    o.push_str("<h2>Scan configuration</h2>\n<div class=kv>\n");
    o.push_str(&format!(
        "<div>Egresses</div><div>{}</div>\n<div>Circuits requested</div><div>{}</div>\n<div>Browser profile</div><div>{}</div>\n<div>Browser</div><div>{}</div>\n<div>Page mode</div><div>{}</div>\n<div>Probe timeout</div><div>{} s</div>\n",
        esc(&r.config.egresses.join(", ")),
        r.config.circuits,
        esc(&r.config.profile),
        esc(&r.config.browser),
        esc(&r.config.mode),
        r.config.probe_timeout_secs
    ));
    o.push_str("</div>\n");

    o.push_str("<h2>Lab</h2>\n<div class=kv>\n");
    o.push_str(&format!(
        "<div>HTTP</div><div>{}</div>\n<div>TLS sniffer</div><div>{}</div>\n<div>SSH sniffer</div><div>{}</div>\n<div>Page mode</div><div>{}</div>\n<div>probe.js SHA-256</div><div class=hash>{}</div>\n<div>Planted leaks</div><div>{}</div>\n",
        esc(&r.lab.http),
        esc(&r.lab.tls),
        esc(&r.lab.ssh),
        esc(&r.lab.mode),
        esc(&r.lab.probe_js_sha256),
        esc(&r.lab.planted.join(", "))
    ));
    o.push_str("</div>\n");

    o.push_str(
        "<h2>Environment inventory</h2>\n<table><tr><th>Tool</th><th>Version / state</th></tr>\n",
    );
    for (k, v) in &r.tool.environment {
        o.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            esc(k),
            esc(v)
        ));
    }
    o.push_str("</table>\n");

    if !r.notes.is_empty() {
        o.push_str("<h2>Notes</h2><ul>\n");
        for n in &r.notes {
            o.push_str(&format!("<li>{}</li>\n", esc(n)));
        }
        o.push_str("</ul>\n");
    }

    o.push_str("<h2>Timings</h2><table><tr><th>Stage</th><th>Seconds</th></tr>\n");
    for (k, v) in &r.timings {
        o.push_str(&format!("<tr><td>{}</td><td>{v:.2}</td></tr>\n", esc(k)));
    }
    o.push_str("</table>\n");

    o.push_str(
        "<details><summary>full report as JSON (this file is self-contained)</summary><pre>",
    );
    o.push_str(&esc(&serde_json::to_string_pretty(r).unwrap_or_default()));
    o.push_str("</pre></details>\n");

    o.push_str(&format!(
        "<footer>hardvoy {} — report {} — {} — all measurements taken locally against a lab on 127.0.0.1; no third-party host was contacted.</footer>\n",
        esc(&r.tool.version),
        esc(&r.id),
        esc(&r.generated_at)
    ));
    o.push_str("</main></body></html>\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let mut r = Report {
            schema: SCHEMA.into(),
            id: "test1".into(),
            generated_at: "2026-01-01T00:00:00Z".into(),
            tool: ToolInfo {
                name: "hardvoy".into(),
                version: "0.1.0".into(),
                environment: vec![("tor".into(), "0.4.9.14".into())],
            },
            host: HostInfo {
                hostname: "h".into(),
                kernel: "7.3.0".into(),
                os: "Arch".into(),
                arch: "x86_64".into(),
                cpus: 6,
                memtotal_kb: 16_000_000,
                timezone: "UTC".into(),
                locale: "C.UTF-8".into(),
                display: "wayland".into(),
            },
            lab: LabInfo {
                http: "127.0.0.1:1".into(),
                tls: "127.0.0.1:2".into(),
                ssh: "127.0.0.1:3".into(),
                mode: "leaky".into(),
                probe_js_sha256: "abc".into(),
                planted: vec!["webrtc-ice-host-candidates".into()],
            },
            config: ConfigView {
                egresses: vec!["direct".into(), "tor".into()],
                circuits: 3,
                profile: "leaky".into(),
                browser: "firefox".into(),
                mode: "leaky".into(),
                probe_timeout_secs: 90,
                stability_runs: 0,
                stability_profiles: vec![],
            },
            ..Default::default()
        };
        let mut e1 = EgressView {
            name: "direct".into(),
            kind: "direct".into(),
            proxy: "127.0.0.1:9".into(),
            url: "http://127.0.0.1:1/".into(),
            ..Default::default()
        };
        let mut b = BrowserView::default();
        b.groups.insert("canvas".into(), "aaaa1111".into());
        b.groups.insert("clock".into(), "cccc3333".into());
        b.user_agent = Some("Firefox".into());
        e1.browser = Some(b);
        e1.tls.push(TlsView {
            variant: "stock".into(),
            ours: crate::tlsf::TlsSummary::default(),
            ..Default::default()
        });
        e1.http.push(HttpView {
            seen_by: "lab".into(),
            order_hash: "h1".into(),
            content_hash: "c1".into(),
            ..Default::default()
        });
        let mut e2 = EgressView {
            name: "tor-circuit-1".into(),
            kind: "tor".into(),
            proxy: "127.0.0.1:10".into(),
            onion: Some("x.onion".into()),
            url: "http://x.onion/".into(),
            ..Default::default()
        };
        let mut b2 = BrowserView::default();
        b2.groups.insert("canvas".into(), "aaaa1111".into());
        b2.groups.insert("clock".into(), "zzzz9999".into());
        b2.user_agent = Some("Firefox".into());
        e2.browser = Some(b2);
        e2.tls.push(TlsView {
            variant: "stock".into(),
            ours: crate::tlsf::TlsSummary::default(),
            ..Default::default()
        });
        e2.http.push(HttpView {
            seen_by: "lab".into(),
            order_hash: "h1".into(),
            content_hash: "c2".into(),
            ..Default::default()
        });
        r.egresses = vec![e1, e2];
        r.correlation = correlate(&r.egresses);
        r.findings.push(Finding {
            id: "F1".into(),
            severity: "high".into(),
            title: "WebRTC leak <x>".into(),
            detail: "192.168.1.5".into(),
            evidence: vec!["candidate:0 1 UDP 1 192.168.1.5 7 typ host".into()],
            recommendation: "disable".into(),
            egress: "direct".into(),
        });
        r.circuits.push(CircuitView {
            label: "circuit-1".into(),
            onion: "x.onion".into(),
            purpose: "general".into(),
            state: "BUILT".into(),
            path_fingerprints: vec!["A".into(), "B".into()],
            exit_fingerprint: Some("B".into()),
            probe_status: 200,
            ..Default::default()
        });
        r
    }

    #[test]
    fn correlate_spots_shared_and_divergent_fingerprints() {
        let r = sample();
        let names_shared: Vec<String> = r
            .correlation
            .shared
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        let names_diff: Vec<String> = r
            .correlation
            .divergent
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        assert!(names_shared.contains(&"canvas".to_string()));
        assert!(names_shared.contains(&"user-agent".to_string()));
        assert!(names_diff.contains(&"clock".to_string()));
        assert!(names_diff.contains(&"http-content".to_string()));
        assert!(matches!(r.correlation.risk.as_str(), "high" | "medium"));
    }

    #[test]
    fn single_egress_reports_that_nothing_was_correlated() {
        let mut r = sample();
        r.egresses.truncate(1);
        let c = correlate(&r.egresses);
        assert_eq!(c.risk, "not-measured");
    }

    #[test]
    fn html_is_self_contained_and_covers_every_section() {
        let r = sample();
        let h = html(&r);
        for need in [
            "hardvoy — operator leak audit",
            "Fingerprint divergence across egresses",
            "WebRTC",
            "Tor circuits",
            "<style>",
            "canvas",
            "class=\"diff\"",
            "class=\"same\"",
            "192.168.1.5",
        ] {
            assert!(h.contains(need), "html missing {need}");
        }
        // no external assets and no scripts: renders offline
        assert!(!h.contains("<script"));
        assert!(!h.contains("src="));
        assert!(!h.contains("href=\"http"));
        assert!(h.ends_with("</html>\n"));
    }

    #[test]
    fn html_escapes_untrusted_probe_text() {
        let mut r = sample();
        r.egresses[0].url = "<img src=x onerror=alert(1)>".into();
        let h = html(&r);
        assert!(!h.contains("<img src=x"));
        assert!(h.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn json_round_trips_through_serde() {
        let r = sample();
        let j = serde_json::to_string(&r).unwrap();
        let back: Report = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id, r.id);
        assert_eq!(back.egresses.len(), 2);
        assert_eq!(back.correlation.risk, r.correlation.risk);
    }

    #[test]
    fn fingerprint_of_reads_each_family() {
        let r = sample();
        let e = &r.egresses[0];
        assert_eq!(fingerprint_of(e, "canvas").as_deref(), Some("aaaa1111"));
        assert_eq!(
            fingerprint_of(e, "http-header-order").as_deref(),
            Some("h1")
        );
        assert!(fingerprint_of(e, "ssh-hassh").is_none());
        assert!(fingerprint_of(e, "not-a-group").is_none());
    }
}
