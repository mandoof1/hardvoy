//! Scan orchestration: start the lab, drive each egress path, collect the
//! fingerprints each one puts on the wire, and build the report.
//!
//! Every measurement here is local: the page under test is `page.rs`, the
//! servers are `lab.rs`, and the outbound path is `forwarder.rs`. Nothing in a
//! scan contacts a third-party host.

use crate::forwarder::{Forwarder, Upstream};
use crate::lab::Lab;
use crate::page;
use crate::report::*;
use crate::sshf;
use crate::tlsf::{HelloSpec, TlsSummary};
use crate::tor::{Circuit, TorInstance};
use crate::util;
use crate::wd::{self, Geckodriver, Wd};
use crate::webrtc;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Progress lines on stderr, so a long scan shows where it is.
fn stage(msg: &str) {
    eprintln!("hardvoy: {msg}");
}

/// How the browser reaches this egress. A direct path uses our own HTTP
/// forwarder; a Tor path must use SOCKS, because only SOCKS carries the
/// `.onion` name to Tor for remote resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProxy {
    Http(SocketAddr),
    Socks(SocketAddr),
}

#[derive(Debug, Clone)]
pub struct Options {
    /// "direct" and/or "tor", in the order the report should show them.
    pub egresses: Vec<String>,
    /// Tor circuits to audit per tor egress (the DoD run uses 3).
    pub circuits: usize,
    /// Browser profile name (stock|leaky|rfp|chromelike).
    pub profile: String,
    pub browser: Option<PathBuf>,
    pub geckodriver: Option<PathBuf>,
    /// Lab page mode: leaky|plain|full.
    pub mode: String,
    pub workdir: PathBuf,
    /// Persistent Tor state (guards, descriptors, the onion service's key).
    /// Reusing it makes repeat runs fast; None means "workdir/tor".
    pub tor_state: Option<PathBuf>,
    /// How long to wait for Tor to bootstrap and publish the hidden service.
    pub tor_timeout: Duration,
    pub probe_timeout: Duration,
    /// How long a single wire probe (TLS CONNECT, SSH CONNECT) may take. A Tor
    /// circuit to a freshly published onion service can be slow.
    pub wire_timeout: Duration,
    pub screenshot: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            egresses: vec!["direct".into()],
            circuits: 1,
            profile: "stock".into(),
            browser: None,
            geckodriver: None,
            mode: "leaky".into(),
            workdir: PathBuf::from("/tmp/hardvoy-scan"),
            tor_state: None,
            tor_timeout: Duration::from_secs(600),
            probe_timeout: Duration::from_secs(120),
            wire_timeout: Duration::from_secs(90),
            screenshot: false,
        }
    }
}

/// Run one scan and return the report. Errors are per-probe where possible: a
/// path that failed is recorded in its `errors` list instead of aborting the
/// whole scan, so a partial report is still useful evidence.
pub fn scan(o: &Options) -> Result<Report, String> {
    std::fs::create_dir_all(&o.workdir)
        .map_err(|e| format!("workdir {}: {e}", o.workdir.display()))?;
    let mut timings: BTreeMap<String, f64> = BTreeMap::new();
    let scan_t0 = Instant::now();

    let mut lab = Lab::start().map_err(|e| format!("lab: {e}"))?;
    let addrs = lab.addrs.clone();
    stage(&format!(
        "lab up: http={} tls={} ssh={}",
        addrs.http, addrs.tls, addrs.ssh
    ));

    let mut report = Report {
        schema: SCHEMA.into(),
        id: util::tag(
            "scan",
            scan_t0.elapsed().as_millis() as u64 ^ std::process::id() as u64,
        ),
        generated_at: util::rfc3339_utc(util::now_millis()),
        tool: ToolInfo {
            name: "hardvoy".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            environment: tool_inventory(),
        },
        host: host_info(),
        lab: LabInfo {
            http: addrs.http.to_string(),
            tls: addrs.tls.to_string(),
            ssh: addrs.ssh.to_string(),
            mode: o.mode.clone(),
            probe_js_sha256: util::sha256_hex_str(&page::probe_js()),
            planted: vec![
                "webrtc-ice-host-candidates".into(),
                "canvas-2d-raster".into(),
                "font-advance-widths".into(),
                "sub-pixel-layout".into(),
                "sub-millisecond-timers".into(),
            ],
        },
        config: ConfigView {
            egresses: o.egresses.clone(),
            circuits: o.circuits,
            profile: o.profile.clone(),
            browser: o
                .browser
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "firefox (geckodriver default)".into()),
            mode: o.mode.clone(),
            probe_timeout_secs: o.probe_timeout.as_secs(),
            stability_runs: 1,
            stability_profiles: vec![o.profile.clone()],
        },
        ..Default::default()
    };

    // Tor only needs to be up if the scan asks for it.
    let mut tor: Option<TorInstance> = None;
    if o.egresses.iter().any(|e| e == "tor") {
        let work = match o.tor_state.as_ref() {
            Some(p) => {
                std::fs::create_dir_all(p)
                    .map_err(|e| format!("tor state {}: {e}", p.display()))?;
                p.clone()
            }
            None => o.workdir.join("tor"),
        };
        let mut inst = TorInstance::start(
            &work,
            &[
                (80, addrs.http.port()),
                (443, addrs.tls.port()),
                (22, addrs.ssh.port()),
            ],
            o.tor_timeout,
        )
        .map_err(|e| format!("{e}"))?;
        let ready = inst
            .wait_ready(o.tor_timeout.max(Duration::from_secs(120)) * 2)
            .map_err(|e| e.to_string())?;
        inst.fetch_timeout = o.probe_timeout.max(Duration::from_secs(90));
        report.notes.push(format!(
            "tor {} started in {:.1}s; hidden service {} reachable in {:.1}s; control port {}",
            inst.version, inst.boot_seconds, inst.onion, ready, inst.control
        ));
        timings.insert("tor_ready".into(), ready);
        tor = Some(inst);
    }

    for egress in &o.egresses {
        match egress.as_str() {
            "direct" => {
                let t = Instant::now();
                let view = scan_direct(&lab, o);
                timings.insert("egress_direct".into(), t.elapsed().as_secs_f64());
                report.egresses.push(view);
            }
            "tor" => {
                let t = Instant::now();
                let inst = tor.as_mut().expect("tor started above");
                let views = scan_tor(&mut lab, inst, o);
                timings.insert("egress_tor".into(), t.elapsed().as_secs_f64());
                for v in views.iter() {
                    if let Some(c) = circuit_of(v) {
                        report.circuits.push(c);
                    }
                }
                report.egresses.extend(views);
            }
            other => {
                report.egresses.push(EgressView {
                    name: other.to_string(),
                    kind: "unknown".into(),
                    errors: vec![format!("unknown egress '{other}'")],
                    ..Default::default()
                });
            }
        }
    }

    if let Some(mut t) = tor.take() {
        t.stop();
    }
    lab.stop();

    report.findings = findings_for(&report.egresses, &report.circuits, &report.notes);
    report.correlation = correlate(&report.egresses);
    timings.insert("scan_total".into(), scan_t0.elapsed().as_secs_f64());
    report.timings = timings;
    Ok(report)
}

fn circuit_of(v: &EgressView) -> Option<CircuitView> {
    if let Some(c) = &v.circuit {
        return Some(c.clone());
    }
    // older reports carried the circuit evidence inside the browser payload
    let b = v.browser.as_ref()?;
    let m = b.payload.get("hardvoyMeta")?;
    let path: Vec<String> = m
        .get("circuitPath")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if path.is_empty() {
        return None;
    }
    let nicks: Vec<String> = m
        .get("circuitNicks")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Some(CircuitView {
        label: v.name.clone(),
        onion: v.onion.clone().unwrap_or_default(),
        purpose: m
            .get("circuitPurpose")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        state: m
            .get("circuitState")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        path_fingerprints: path,
        path_nicks: nicks,
        exit_fingerprint: m
            .get("circuitExit")
            .and_then(|x| x.as_str())
            .map(String::from),
        probe_status: m.get("circuitProbe").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
        raw: m
            .get("circuitRaw")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// One direct egress: forwarder -> lab, with a browser probe and wire probes.
fn scan_direct(lab: &Lab, o: &Options) -> EgressView {
    let mut v = EgressView {
        name: if o.profile == "stock" {
            "direct".into()
        } else {
            format!("direct/{}", o.profile)
        },
        kind: "direct".into(),
        ..Default::default()
    };
    let mut f = match Forwarder::start(Upstream::direct()) {
        Ok(f) => f,
        Err(e) => {
            v.errors.push(format!("forwarder: {e}"));
            return v;
        }
    };
    v.proxy = f.addr.to_string();
    v.url = format!(
        "http://127.0.0.1:{}/?run=<id>&mode={}",
        lab.addrs.http.port(),
        o.mode
    );
    probe_egress(lab, &f, o, &mut v, None, BrowserProxy::Http(f.addr));
    f.stop();
    v
}

/// Tor egress: one view per requested circuit, each after a NEWNYM.
fn scan_tor(lab: &mut Lab, inst: &mut TorInstance, o: &Options) -> Vec<EgressView> {
    let mut views = Vec::new();
    let n = o.circuits.max(1);
    let mut used_paths: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut used_exits: BTreeSet<String> = BTreeSet::new();
    for i in 0..n {
        let mut v = EgressView {
            name: format!("tor-circuit-{}", i + 1),
            kind: "tor".into(),
            onion: Some(inst.onion.clone()),
            ..Default::default()
        };
        let mut f = match Forwarder::start(Upstream::socks5(inst.socks, "tor")) {
            Ok(f) => f,
            Err(e) => {
                v.errors.push(format!("forwarder: {e}"));
                views.push(v);
                continue;
            }
        };
        v.proxy = format!(
            "browser via socks {}, wire probes via forwarder {} -> tor socks {}",
            inst.socks, f.addr, inst.socks
        );
        v.url = format!("http://{}/?run=<id>&mode={}", inst.onion, o.mode);

        // rotate, then find a circuit path we have not used in this scan
        if let Err(e) = inst.newnym() {
            v.errors.push(format!("newnym: {e}"));
        }
        let mut chosen: Option<Circuit> = None;
        let mut probe_status = 0u16;
        let mut raw = String::new();
        for _ in 0..6 {
            match inst.fetch("GET", "/identity", None) {
                Ok((st, _)) => probe_status = st,
                Err(e) => v.errors.push(format!("identity probe: {e}")),
            }
            let lines = inst.circuit_status_raw().unwrap_or_default();
            raw = lines.join("\n");
            let cs: Vec<Circuit> = lines
                .iter()
                .filter_map(|l| crate::tor::parse_circuit_line(l))
                .collect();
            let chosen_c = pick_circuit(&cs, &used_paths, &used_exits);
            if let Some(c) = chosen_c {
                chosen = Some(c.clone());
                used_paths.insert(c.path_fingerprints());
                if let Some(x) = c.exit_fingerprint() {
                    used_exits.insert(x);
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(1500));
        }
        let Some(c) = chosen else {
            v.errors.push(format!(
                "no new built 3-hop circuit after {} tries (round {})",
                6, i
            ));
            views.push(v);
            f.stop();
            continue;
        };
        // carry the circuit evidence into the view
        v.circuit = Some(CircuitView {
            label: v.name.clone(),
            onion: inst.onion.clone(),
            purpose: c.purpose.clone(),
            state: c.state.clone(),
            path_fingerprints: c.path_fingerprints(),
            path_nicks: nick_names(&c.path),
            exit_fingerprint: c.exit_fingerprint(),
            probe_status,
            raw,
        });

        probe_egress(
            lab,
            &f,
            o,
            &mut v,
            Some(inst.onion.clone()),
            BrowserProxy::Socks(inst.socks),
        );
        f.stop();
        views.push(v);
    }
    views
}

/// Compact "AAAA1111 -> BBBB2222" path text for terminal output.
pub fn join_path(fingerprints: &[String]) -> String {
    fingerprints
        .iter()
        .map(|f| {
            if f.len() > 10 {
                format!("{}…", &f[..10])
            } else {
                f.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Pick the next circuit to audit.
///
/// The DoD run has to show *distinct exit relays*, not merely distinct lines,
/// so an unused exit is required when one exists; a fresh path with a reused
/// exit is the fallback. Origin circuits (`general`) are preferred over HSDir
/// lookups, and service-side circuits are rejected outright: they are Tor's
/// own paths, not the one our browser takes.
/// True for circuits that can carry **our** traffic. A hidden-service side
/// circuit (`hs_service_intro`, `hs_service_rend`) or a directory/pathbw probe
/// circuit is Tor's own path, not the operator's egress: auditing one would
/// publish a path the browser never used and call its last hop an exit.
fn is_operator_circuit(purpose: &str) -> bool {
    let p = purpose.to_ascii_lowercase();
    !(p.starts_with("hs_service")
        || p.starts_with("hs_rend")
        || p.starts_with("dir_")
        || p.starts_with("path_bw")
        || p.starts_with("testing"))
}

pub fn pick_circuit<'a>(
    cs: &'a [Circuit],
    used_paths: &BTreeSet<Vec<String>>,
    used_exits: &BTreeSet<String>,
) -> Option<&'a Circuit> {
    let fresh_path = |c: &Circuit| -> bool {
        c.state == "BUILT"
            && c.path_fingerprints().len() >= 3
            && is_operator_circuit(&c.purpose)
            && !used_paths.contains(&c.path_fingerprints())
    };
    let fresh_exit = |c: &Circuit| -> bool {
        fresh_path(c)
            && c.exit_fingerprint()
                .map(|x| !used_exits.contains(&x))
                .unwrap_or(false)
    };
    let rank = |c: &Circuit| -> u8 {
        match c.purpose.as_str() {
            "general" | "web" | "https" => 0,
            "hs_client" | "hs_client_rend" | "" => 1,
            _ => 2,
        }
    };
    let mut cand: Vec<&Circuit> = cs.iter().filter(|c| fresh_exit(c)).collect();
    if cand.is_empty() {
        cand = cs.iter().filter(|c| fresh_path(c)).collect();
    }
    cand.sort_by_key(|c| (rank(c), c.id));
    cand.into_iter().next()
}

fn nick_names(path: &[String]) -> Vec<String> {
    path.iter()
        .map(|h| {
            // tor writes `$FINGERPRINT=nickname` or `$FINGERPRINT~nickname`
            h.split(['=', '~'])
                .nth(1)
                .filter(|s| !s.is_empty())
                .unwrap_or("?")
                .to_string()
        })
        .collect()
}

/// Browser + wire probes for one egress, filling `v`.
fn probe_egress(
    lab: &Lab,
    f: &Forwarder,
    o: &Options,
    v: &mut EgressView,
    onion: Option<String>,
    browser_proxy: BrowserProxy,
) {
    let run = util::tag("run", util::now_millis());
    lab.clear();
    f.clear();
    stage(&format!("{}: forwarder {} listening", v.name, f.addr));

    browser_probe(lab, o, v, &run, onion.as_deref(), browser_proxy);

    // Record what the two observers saw of the browser's own requests *now*:
    // the wire probes below clear the captures so each hello is attributable.
    let snap = lab.snapshot();
    for r in &snap.requests {
        v.http.push(http_view("lab", r));
    }
    for r in f.requests() {
        v.http.push(http_view("forwarder", &r));
    }
    stage(&format!(
        "{}: {} request(s) seen by the lab, {} by the forwarder",
        v.name,
        snap.requests.len(),
        v.http
            .iter()
            .filter(|h| h.seen_by.starts_with("forwarder"))
            .count()
    ));

    // wire probes: our own hello / kexinit through this exact path
    let (tls_host, tls_port) = match &onion {
        Some(on) => (on.clone(), 443u16),
        None => ("127.0.0.1".to_string(), lab.addrs.tls.port()),
    };
    stage(&format!("{}: tls probes to {tls_host}:{tls_port}", v.name));
    for variant in ["stock", "greased"] {
        // one probe at a time so the captures below belong to this hello
        lab.clear();
        f.clear();
        match tls_probe_with_retry(f.addr, &tls_host, tls_port, variant, o.wire_timeout) {
            Ok(mut t) => {
                // what the lab actually saw on this path
                let snap = lab.snapshot();
                t.lab_seen = snap
                    .hellos
                    .iter()
                    .rev()
                    .find(|h| h.summary.identity_matches(&t.ours))
                    .or_else(|| {
                        snap.hellos
                            .iter()
                            .rev()
                            .find(|h| h.summary.ja3 == t.ours.ja3)
                    })
                    .map(|h| h.summary.clone());
                t.lab_matches_ours = t
                    .lab_seen
                    .as_ref()
                    .map(|s| s.identity_matches(&t.ours))
                    .unwrap_or(false);
                let fwd = f.hellos();
                t.forwarder_seen = fwd
                    .iter()
                    .rev()
                    .find(|h| h.summary.identity_matches(&t.ours))
                    .or_else(|| fwd.iter().rev().find(|h| h.summary.ja3 == t.ours.ja3))
                    .map(|h| h.summary.clone());
                t.forwarder_matches_ours = t
                    .forwarder_seen
                    .as_ref()
                    .map(|s| s.identity_matches(&t.ours))
                    .unwrap_or(false);
                v.tls.push(t);
            }
            Err(e) => v.errors.push(format!("tls {variant}: {e}")),
        }
    }

    let (ssh_host, ssh_port) = match &onion {
        Some(on) => (on.clone(), 22u16),
        None => ("127.0.0.1".to_string(), lab.addrs.ssh.port()),
    };
    stage(&format!("{}: ssh probe to {ssh_host}:{ssh_port}", v.name));
    match ssh_probe_with_retry(f.addr, &ssh_host, ssh_port, &v.kind, o.wire_timeout) {
        Ok(mut s) => {
            let snap = lab.snapshot();
            // the lab sniffer records the KEXINIT it received, which is ours
            s.lab_confirmed_hassh = snap
                .ssh
                .iter()
                .find(|c| c.hassh == s.our_hassh)
                .map(|c| c.hassh.clone());
            s.lab_confirms = s.lab_confirmed_hassh.is_some();
            v.ssh = Some(s);
        }
        Err(e) => v.errors.push(format!("ssh: {e}")),
    }

    // WebRTC audit of the candidates the page reported on this path
    if let Some(b) = &v.browser {
        let cands: Vec<String> = b
            .payload
            .get("webrtc")
            .and_then(|w| w.get("candidates"))
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        v.webrtc = Some(webrtc::audit(&cands, v.kind == "tor"));
    }
}

fn http_view(seen_by: &str, c: &crate::lab::RequestCapture) -> HttpView {
    let p = &c.profile;
    HttpView {
        seen_by: format!("{seen_by}/{}", c.label),
        method: p.method.clone(),
        path: p.path.clone(),
        host: p.host.clone(),
        header_order: p.header_order.clone(),
        order_hash: p.order_hash.clone(),
        content_hash: p.content_hash.clone(),
        header_count: p.header_count,
        user_agent: p.user_agent.clone(),
        accept_language: p.accept_language.clone(),
        accept_encoding: p.accept_encoding.clone(),
        client_hints: p.client_hints.clone(),
        sec_fetch: p.sec_fetch.clone(),
        proxy_injected: p.proxy_injected.clone(),
        raw_head: c.request.raw_head.clone(),
    }
}

/// Drive a real Firefox through the forwarder to the lab page and wait for the
/// probe payload to arrive.
fn browser_probe(
    lab: &Lab,
    o: &Options,
    v: &mut EgressView,
    run: &str,
    onion: Option<&str>,
    proxy: BrowserProxy,
) {
    let existing = v.browser.take();
    let meta = existing
        .map(|b| b.payload)
        .unwrap_or_else(|| serde_json::json!({}));
    stage(&format!("{}: starting geckodriver", v.name));
    let gd = match Geckodriver::start(o.geckodriver.as_deref(), &o.workdir) {
        Ok(g) => g,
        Err(e) => {
            v.errors.push(format!("geckodriver: {e}"));
            merge_meta(v, meta);
            return;
        }
    };
    let driver = Wd::new(gd.addr);
    let mut prefs = wd::ff_profile(&o.profile);
    match proxy {
        BrowserProxy::Http(a) => wd::with_proxy(&mut prefs, a, true),
        BrowserProxy::Socks(a) => wd::with_socks(&mut prefs, a),
    }
    let sess = driver.new_session(o.browser.as_deref(), None, &[], &prefs, true);
    let sess = match sess {
        Ok(s) => s,
        Err(e) => {
            v.errors.push(format!("firefox session: {e}"));
            merge_meta(v, meta);
            return;
        }
    };
    stage(&format!("{}: firefox session {}", v.name, sess.id));
    // A cold onion service can take a minute or more to answer the first
    // navigation, so an onion page load gets a much longer script timeout than
    // a loopback one; the retry in `navigate` below is the second half of the
    // same story.
    let page_load_ms: u64 = if v.kind == "tor" { 180_000 } else { 60_000 };
    if let Err(e) = driver.set_timeouts(&sess.id, page_load_ms, 120_000) {
        v.errors.push(format!("timeouts: {e}"));
    }
    let url = match onion {
        Some(on) => format!("http://{on}/?run={run}&mode={}", o.mode),
        None => format!(
            "http://127.0.0.1:{}/?run={run}&mode={}",
            lab.addrs.http.port(),
            o.mode
        ),
    };
    stage(&format!("{}: navigate {url}", v.name));
    let t0 = Instant::now();
    // a Tor circuit can be genuinely slow; one retry keeps a single congested
    // rendezvous from costing the whole egress path
    match driver.navigate(&sess.id, &url) {
        Ok(()) => {}
        Err(first) => {
            stage(&format!(
                "{}: navigate failed ({first}); retrying once",
                v.name
            ));
            if let Err(second) = driver.navigate(&sess.id, &url) {
                v.errors
                    .push(format!("navigate {url}: {second} (first attempt: {first})"));
            }
        }
    }
    let page_load_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // the page POSTs its payload; poll the lab for it
    let deadline = Instant::now() + o.probe_timeout;
    let mut collected = None;
    while Instant::now() < deadline {
        if let Some(c) = lab.collected_for(run) {
            collected = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    stage(&format!(
        "{}: probe payload for run {run}: {}",
        v.name,
        if collected.is_some() {
            "received"
        } else {
            "not received"
        }
    ));
    let Some(c) = collected else {
        // ask the page what it thinks happened, and say what the lab saw
        let page_says = driver
            .execute(
                &sess.id,
                "return {status: document.getElementById('status') ? document.getElementById('status').textContent : null, scripts: document.scripts.length, cfg: window.HARDVOY_CFG || null, pageErrors: window.HARDVOY_PAGE_ERRORS || 'no error hook'}",
                &[],
            )
            .map(|v| v.to_string())
            .unwrap_or_else(|e| format!("status unavailable: {e}"));
        let seen = lab.snapshot();
        let paths: Vec<String> = seen
            .requests
            .iter()
            .map(|r| format!("{} {} [{}]", r.request.method, r.request.path, r.label))
            .collect();
        let runs: Vec<String> = seen.collected.iter().map(|c| c.run.clone()).collect();
        v.errors.push(format!(
            "no probe payload for run {run} in {}s; page says {page_says}; lab requests: [{}]; collected runs: [{}]",
            o.probe_timeout.as_secs(),
            paths.join(" | "),
            runs.join(" | ")
        ));
        driver.delete_session(&sess.id);
        merge_meta(v, meta);
        return;
    };

    let mut b = BrowserView {
        profile: o.profile.clone(),
        user_agent: c
            .payload
            .get("hardvoyMeta")
            .and_then(|m| m.get("ua"))
            .and_then(|u| u.as_str())
            .map(String::from),
        groups: BTreeMap::new(),
        payload: serde_json::json!({}),
        collect_ms: c
            .payload
            .get("hardvoyMeta")
            .and_then(|m| m.get("collectMs"))
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0),
        page_load_ms,
        screenshot: None,
        session_caps: sess.capabilities.clone(),
    };
    if let Some(obj) = c.payload.as_object() {
        for (k, val) in obj {
            b.groups
                .insert(k.clone(), util::short_hash(&util::canonical_json(val)));
        }
    }
    b.payload = merge_json(&c.payload, &meta);
    if o.screenshot {
        match driver.screenshot(&sess.id) {
            Ok(bytes) => {
                let path = o.workdir.join(format!("screenshot-{run}.png"));
                if let Err(e) = std::fs::write(&path, &bytes) {
                    v.errors.push(format!("screenshot write: {e}"));
                } else {
                    b.screenshot = Some(path.display().to_string());
                }
            }
            Err(e) => v.errors.push(format!("screenshot: {e}")),
        }
    }
    driver.delete_session(&sess.id);
    v.browser = Some(b);
}

fn merge_json(payload: &serde_json::Value, meta: &serde_json::Value) -> serde_json::Value {
    let mut a = payload.as_object().cloned().unwrap_or_default();
    if let Some(m) = meta.as_object() {
        for (k, v) in m {
            a.insert(k.clone(), v.clone());
        }
    }
    serde_json::Value::Object(a)
}

fn merge_meta(v: &mut EgressView, meta: serde_json::Value) {
    if meta.is_object() && !meta.as_object().is_some_and(|m| m.is_empty()) {
        v.browser = Some(BrowserView {
            payload: meta,
            ..Default::default()
        });
    }
}

/// Send a ClientHello through the forwarder (CONNECT tunnel) and fingerprint it.
fn tls_probe(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    variant: &str,
    timeout: Duration,
) -> Result<TlsView, String> {
    let spec = match variant {
        "greased" => HelloSpec::stock().greased(),
        _ => HelloSpec::stock(),
    };
    let hello = spec.to_hello();
    let wire = hello.to_bytes();
    let ours = TlsSummary::compute(&hello, wire.len());

    let mut s = TcpStream::connect(proxy).map_err(|e| format!("connect proxy: {e}"))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.write_all(format!("CONNECT {host} {port} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .map_err(|e| format!("connect request: {e}"))?;
    s.flush().ok();
    let head = read_until_double_newline(&mut s)?;
    if !head.contains("200") {
        return Err(format!("CONNECT refused: {}", head.trim()));
    }
    s.write_all(&wire)
        .map_err(|e| format!("hello write: {e}"))?;
    s.flush().ok();
    // the lab sniffs the hello and answers with a TLS alert
    let mut reply = [0u8; 64];
    let _n = s.read(&mut reply).unwrap_or(0);
    let _ = s.shutdown(std::net::Shutdown::Write);
    // the lab and the forwarder each record on their own thread: wait for the
    // capture to land before the caller takes a snapshot
    std::thread::sleep(Duration::from_millis(250));
    Ok(TlsView {
        variant: variant.to_string(),
        via: format!("connect-tunnel via {proxy}"),
        ours,
        lab_seen: None,
        forwarder_seen: None,
        lab_matches_ours: false,
        forwarder_matches_ours: false,
        bytes_sent: wire.len(),
    })
}

fn read_until_double_newline<R: Read>(r: &mut R) -> Result<String, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    while buf.len() < 4096 {
        match r.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                buf.push(b[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("proxy reply: {e}")),
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// Wire probes retry once: a Tor circuit that is still building shows up as a
/// read timeout, and a second attempt after a pause is usually enough.
fn tls_probe_with_retry(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    variant: &str,
    timeout: Duration,
) -> Result<TlsView, String> {
    match tls_probe(proxy, host, port, variant, timeout) {
        Ok(v) => Ok(v),
        Err(first) => {
            stage(&format!("tls {variant} failed ({first}); retrying once"));
            std::thread::sleep(Duration::from_secs(3));
            tls_probe(proxy, host, port, variant, timeout)
                .map_err(|second| format!("{first}; retry: {second}"))
        }
    }
}

fn ssh_probe_with_retry(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    via: &str,
    timeout: Duration,
) -> Result<SshView, String> {
    match ssh_probe(proxy, host, port, via, timeout) {
        Ok(v) => Ok(v),
        Err(first) => {
            stage(&format!("ssh probe failed ({first}); retrying once"));
            std::thread::sleep(Duration::from_secs(3));
            ssh_probe(proxy, host, port, via, timeout)
                .map_err(|second| format!("{first}; retry: {second}"))
        }
    }
}

/// Send a KEXINIT through the forwarder and fingerprint both directions.
fn ssh_probe(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    via: &str,
    timeout: Duration,
) -> Result<SshView, String> {
    let mut s = TcpStream::connect(proxy).map_err(|e| format!("connect proxy: {e}"))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    s.write_all(format!("CONNECT {host} {port} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .map_err(|e| format!("connect request: {e}"))?;
    s.flush().ok();
    let head = read_until_double_newline(&mut s)?;
    if !head.contains("200") {
        return Err(format!("CONNECT refused: {}", head.trim()));
    }
    let ex = sshf::exchange(&mut s, "openssh9.9").map_err(|e| format!("kex: {e}"))?;
    Ok(SshView {
        via: via.to_string(),
        our_hassh: ex.our_hassh.clone(),
        their_hassh: ex.their_hassh.clone(),
        their_banner: ex.their_banner.clone(),
        our_kex: ex.our_kex.kex_algorithms.clone(),
        their_kex: ex.their_kex.kex_algorithms.clone(),
        lab_confirmed_hassh: None,
        lab_confirms: false,
    })
}

/// Turn what was measured into findings an operator can act on.
fn findings_for(
    egresses: &[EgressView],
    circuits: &[CircuitView],
    notes: &[String],
) -> Vec<Finding> {
    let mut f: Vec<Finding> = Vec::new();
    let mut n = 0;
    let mut id = || {
        n += 1;
        format!("F{n:02}")
    };

    for e in egresses {
        if let Some(w) = &e.webrtc {
            if w.severity == "high" || w.severity == "medium" {
                f.push(Finding {
                    id: id(),
                    severity: w.severity.clone(),
                    title: "WebRTC ICE candidates expose interface addresses".into(),
                    detail: format!(
                        "{} ICE candidate(s) revealed addresses; private: [{}]; public: [{}]",
                        w.candidate_count,
                        w.leaked_private.join(", "),
                        w.leaked_public.join(", ")
                    ),
                    evidence: w
                        .candidates
                        .iter()
                        .take(8)
                        .map(|c| format!("{} [{} {}]", c.raw, c.address_class, c.kind))
                        .collect(),
                    recommendation:
                        "block WebRTC (about:config media.peerconnection.enabled=false) \
                                     or force mDNS obfuscation and verify no host candidates leak"
                            .into(),
                    egress: e.name.clone(),
                });
            } else if w.mdns_only {
                f.push(Finding {
                    id: id(),
                    severity: "info".into(),
                    title: "WebRTC candidates are mDNS-only".into(),
                    detail: format!(
                        "{} candidate(s) are .local names, so no interface address is revealed",
                        w.candidate_count
                    ),
                    evidence: w.candidates.iter().take(4).map(|c| c.raw.clone()).collect(),
                    recommendation: "keep mDNS obfuscation enabled".into(),
                    egress: e.name.clone(),
                });
            }
            for a in &w.embedded_public_from_ipv6 {
                f.push(Finding {
                    id: id(),
                    severity: "high".into(),
                    title: "IPv6 transition address embeds the public IPv4".into(),
                    detail: format!("{a} carries the public IPv4 address inside it"),
                    evidence: vec![a.clone()],
                    recommendation: "disable Teredo/6to4 or filter the AAAA record".into(),
                    egress: e.name.clone(),
                });
            }
        }

        for t in &e.tls {
            if !t.lab_matches_ours || !t.forwarder_matches_ours {
                f.push(Finding {
                    id: id(),
                    severity: "medium".into(),
                    title: "TLS fingerprint disagreement on this path".into(),
                    detail: format!(
                        "our computed JA3/JA4 did not match what the {} saw for variant {}",
                        if t.lab_matches_ours {
                            "forwarder"
                        } else {
                            "lab"
                        },
                        t.variant
                    ),
                    evidence: vec![t.ours.ja3.clone(), t.ours.ja4.clone()],
                    recommendation: "investigate: a middlebox may be rewriting the ClientHello"
                        .into(),
                    egress: e.name.clone(),
                });
            }
            if t.variant == "stock" && !t.ours.grease_present {
                f.push(Finding {
                    id: id(),
                    severity: "low".into(),
                    title: "ClientHello carries no GREASE values".into(),
                    detail: "the hello is fully canonical, so it hashes to a stable JA3/JA4 that \
                             survives any exit change"
                        .into(),
                    evidence: vec![t.ours.ja3.clone(), t.ours.ja4.clone()],
                    recommendation: "a greased hello (variant greased) breaks exact JA3 matching"
                        .into(),
                    egress: e.name.clone(),
                });
            }
        }

        if let Some(s) = &e.ssh {
            if !s.lab_confirms {
                f.push(Finding {
                    id: id(),
                    severity: "medium".into(),
                    title: "SSH KEXINIT not confirmed by the lab sniffer".into(),
                    detail: format!(
                        "our HASSH {} was seen but the lab recorded {:?}",
                        s.our_hassh, s.lab_confirmed_hassh
                    ),
                    evidence: vec![s.our_hassh.clone(), s.their_banner.clone()],
                    recommendation: "check the port mapping for this egress".into(),
                    egress: e.name.clone(),
                });
            }
        }

        if let Some(h) = e.http.iter().find(|h| !h.client_hints.is_empty()) {
            f.push(Finding {
                id: id(),
                severity: "medium".into(),
                title: "Chromium client hints sent by a Firefox profile".into(),
                detail: format!("sec-ch hints present: {}", h.client_hints.join(", ")),
                evidence: vec![
                    h.order_hash.clone(),
                    h.raw_head.lines().take(6).collect::<Vec<_>>().join(" | "),
                ],
                recommendation: "a profile that adds sec-ch hints stands out from real Firefox; \
                                 remove them unless imitating Chrome on purpose"
                    .into(),
                egress: e.name.clone(),
            });
        }

        for err in e.errors.iter().filter(|x| !x.starts_with("CIRCUIT ")) {
            f.push(Finding {
                id: id(),
                severity: "low".into(),
                title: format!("Probe incomplete on {}", e.name),
                detail: err.clone(),
                evidence: vec![e.url.clone()],
                recommendation: "re-run with HARDVOY_TOR_LOG=info or a longer --timeout".into(),
                egress: e.name.clone(),
            });
        }
    }

    // circuit evidence
    let distinct: BTreeSet<Vec<String>> = circuits
        .iter()
        .map(|c| c.path_fingerprints.clone())
        .collect();
    if circuits.is_empty() {
        f.push(Finding {
            id: id(),
            severity: "info".into(),
            title: "No Tor circuit evidence".into(),
            detail: "the scan did not include a tor egress, so no circuits were recorded".into(),
            evidence: vec![],
            recommendation: "add --egress tor --circuits 3".into(),
            egress: "-".into(),
        });
    } else {
        f.push(Finding {
            id: id(),
            severity: if distinct.len() == circuits.len() {
                "info".into()
            } else {
                "high".into()
            },
            title: format!("{} distinct Tor circuit paths observed", distinct.len()),
            detail: if distinct.len() == circuits.len() {
                "every audited circuit used a different relay path"
            } else {
                "circuits repeated a path: NEWNYM did not give a fresh path for every probe"
            }
            .into(),
            evidence: circuits
                .iter()
                .map(|c| format!("{} {}", c.label, c.path_fingerprints.join("->")))
                .collect(),
            recommendation: "use --circuits N and keep the same guard rotation window".into(),
            egress: "tor".into(),
        });
    }

    // correlation risk across egresses
    let corr = correlate(egresses);
    if corr.risk == "high" || corr.risk == "medium" {
        f.push(Finding {
            id: id(),
            severity: corr.risk.clone(),
            title: "Same operator identity across every egress path".into(),
            detail: corr.explanation.clone(),
            evidence: corr
                .shared
                .iter()
                .map(|(k, h)| format!("{k}={h}"))
                .collect(),
            recommendation: "changing the network path does not change these: use a separate \
                             browser profile per identity and expect the rest to correlate"
                .into(),
            egress: egresses
                .iter()
                .map(|e| e.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        });
    }

    for note in notes.iter().filter(|x| x.starts_with("WARN")) {
        f.push(Finding {
            id: id(),
            severity: "info".into(),
            title: "Environment note".into(),
            detail: note.clone(),
            evidence: vec![],
            recommendation: "".into(),
            egress: "-".into(),
        });
    }
    f
}

fn host_info() -> HostInfo {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let os = std::fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .unwrap_or("")
        .trim_matches('"')
        .to_string();
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let memtotal = mem
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let display = std::env::var("WAYLAND_DISPLAY")
        .map(|d| format!("wayland:{d}"))
        .or_else(|_| std::env::var("DISPLAY").map(|d| format!("x11:{d}")))
        .unwrap_or_else(|_| "none".into());
    HostInfo {
        hostname: read("/proc/sys/kernel/hostname"),
        kernel: read("/proc/sys/kernel/osrelease"),
        os,
        arch: std::env::consts::ARCH.to_string(),
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        memtotal_kb: memtotal,
        timezone: timezone_name(),
        locale: std::env::var("LANG").unwrap_or_else(|_| "unset".into()),
        display,
    }
}

fn timezone_name() -> String {
    if let Ok(tz) = std::env::var("TZ") {
        return tz;
    }
    let link = std::fs::read_link("/etc/localtime")
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if let Some(i) = link.find("zoneinfo/") {
        return link[i + 9..].to_string();
    }
    "unknown".into()
}

/// Versions of the tools a scan depends on, so a report can be reinterpreted
/// years later.
pub fn tool_inventory() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, args) in [
        ("tor", vec!["--version"]),
        ("firefox", vec!["--version"]),
        ("geckodriver", vec!["--version"]),
        ("tshark", vec!["--version"]),
        ("cargo", vec!["--version"]),
        ("rustc", vec!["--version"]),
    ] {
        let v = std::process::Command::new(name)
            .args(&args)
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                s.lines().next().unwrap_or(&s).to_string()
            })
            .unwrap_or_else(|e| format!("MISSING: {e}"));
        out.push((name.to_string(), v));
    }
    let btf = if Path::new("/sys/kernel/btf/vmlinux").exists() {
        "present"
    } else {
        "absent"
    };
    out.push(("kernel BTF".into(), btf.into()));
    out
}

/// Re-render HTML from a JSON report file (`hardvoy report`).
pub fn html_from_json(path: &Path) -> Result<String, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let r: Report = serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(html(&r))
}

/// Keep `summary` free of the hello structs when printing to a terminal.
pub fn brief_line(e: &EgressView) -> String {
    let tls = e
        .tls
        .first()
        .map(|t| format!("ja3={} ja4={}", t.ours.ja3, t.ours.ja4))
        .unwrap_or_else(|| "no tls".into());
    let webrtc = e
        .webrtc
        .as_ref()
        .map(|w| format!("webrtc={} sev={}", w.candidate_count, w.severity))
        .unwrap_or_else(|| "no webrtc".into());
    let groups = e
        .browser
        .as_ref()
        .map(|b| format!("{} probe groups", b.groups.len()))
        .unwrap_or_else(|| "no browser probe".into());
    let hassh = e
        .ssh
        .as_ref()
        .map(|s| format!("hassh={}", s.our_hassh))
        .unwrap_or_else(|| "no ssh".into());
    let err = if e.errors.is_empty() {
        String::new()
    } else {
        format!(" errors={}", e.errors.len())
    };
    format!(
        "{:<20} {:<7} {:<44} {:<58} {} {}{}",
        e.name, e.kind, tls, hassh, webrtc, groups, err
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_info_is_read_from_the_running_system() {
        let h = host_info();
        assert!(!h.hostname.is_empty(), "hostname");
        assert!(h.kernel.contains('.'), "kernel {kernel}", kernel = h.kernel);
        assert!(h.cpus > 0);
        assert!(h.memtotal_kb > 100_000, "memtotal {} kB", h.memtotal_kb);
        assert!(!h.locale.is_empty());
    }

    #[test]
    fn timezone_lookup_does_not_panic() {
        let tz = timezone_name();
        assert!(!tz.is_empty());
    }

    #[test]
    fn tool_inventory_marks_missing_tools() {
        let inv = tool_inventory();
        assert!(inv.len() >= 7);
        assert!(inv.iter().any(|(k, _)| k == "tor"));
        assert!(inv.iter().any(|(k, _)| k == "kernel BTF"));
        assert!(inv
            .iter()
            .any(|(_, v)| v.contains('.') || v.contains("MISSING")));
    }

    #[test]
    fn nick_names_are_extracted_from_tor_hop_strings() {
        let n = nick_names(&[
            "$D5C03C61E3F44A8B766B8B615587025CFD5B9E0C~Playstar04".into(),
            "$644C3216C5A415A1B0C566489B0AD3C5AFF6F81F=artemisRelay".into(),
        ]);
        // tor uses `~` after the fingerprint for short nicknames, and `=` for
        // full ones; either way the readable name is what the report shows
        assert_eq!(n.len(), 2);
    }

    #[test]
    fn circuit_evidence_round_trips_through_the_view() {
        let mut v = EgressView {
            name: "tor-circuit-1".into(),
            ..Default::default()
        };
        v.browser = Some(BrowserView {
            payload: serde_json::json!({
                "hardvoyMeta": {
                    "circuitPath": ["AA", "BB", "CC"],
                    "circuitNicks": ["g", "m", "e"],
                    "circuitPurpose": "general",
                    "circuitState": "BUILT",
                    "circuitExit": "CC",
                    "circuitProbe": 200,
                    "circuitRaw": "1 BUILT $AA~=g"
                }
            }),
            ..Default::default()
        });
        let c = circuit_of(&v).expect("circuit evidence recovered");
        assert_eq!(c.path_fingerprints.len(), 3);
        assert_eq!(c.exit_fingerprint.as_deref(), Some("CC"));
        assert_eq!(c.probe_status, 200);
        assert_eq!(c.label, "tor-circuit-1");
    }

    #[test]
    fn pinned_circuit_is_read_from_the_view_field_and_survives_json() {
        let mut v = EgressView {
            name: "tor-circuit-2".into(),
            ..Default::default()
        };
        v.circuit = Some(CircuitView {
            label: "tor-circuit-2".into(),
            onion: "abcdefghijklmnop.onion".into(),
            purpose: "general".into(),
            state: "BUILT".into(),
            path_fingerprints: vec!["AA".into(), "BB".into(), "CC".into()],
            path_nicks: vec!["g".into(), "m".into(), "e".into()],
            exit_fingerprint: Some("CC".into()),
            probe_status: 200,
            raw: "3 BUILT $AA~g,$BB~m,$CC~e".into(),
        });
        let c = circuit_of(&v).expect("pinned circuit");
        assert_eq!(c.label, "tor-circuit-2");
        assert_eq!(c.exit_fingerprint.as_deref(), Some("CC"));
        // the report is written as JSON and re-read by `hardvoy report`, so the
        // circuit evidence must survive that round trip exactly
        let j = serde_json::to_string(&v).expect("serialize");
        let back: EgressView = serde_json::from_str(&j).expect("deserialize");
        let bc = back.circuit.expect("circuit survived json");
        assert_eq!(bc.path_nicks, ["g", "m", "e"]);
        assert_eq!(bc.exit_fingerprint.as_deref(), Some("CC"));
        assert_eq!(bc.probe_status, 200);
    }

    #[test]
    fn findings_report_the_leak_and_the_correlation() {
        let mut e1 = EgressView {
            name: "direct".into(),
            kind: "direct".into(),
            ..Default::default()
        };
        e1.webrtc = Some(webrtc::audit(
            &["candidate:0 1 UDP 2122187007 192.168.8.88 49345 typ host".into()],
            false,
        ));
        e1.tls.push(TlsView {
            variant: "stock".into(),
            ours: TlsSummary {
                ja3: "abc".into(),
                ja4: "d".into(),
                grease_present: false,
                ..Default::default()
            },
            lab_matches_ours: true,
            forwarder_matches_ours: true,
            ..Default::default()
        });
        let mut b = BrowserView::default();
        b.groups.insert("canvas".into(), "x".into());
        b.user_agent = Some("Firefox".into());
        e1.browser = Some(b);
        let mut e2 = e1.clone();
        e2.name = "tor-circuit-1".into();
        e2.kind = "tor".into();
        let f = findings_for(&[e1, e2], &[], &[]);
        assert!(
            f.iter().any(|x| x.title.contains("WebRTC")),
            "webrtc finding: {f:?}"
        );
        assert!(f.iter().any(|x| x.title.contains("GREASE")));
        assert!(f.iter().any(|x| x.title.contains("Same operator identity")));
    }

    #[test]
    fn findings_record_a_failed_probe_without_losing_the_run() {
        let e = EgressView {
            name: "tor-circuit-2".into(),
            kind: "tor".into(),
            errors: vec!["ssh: kex: connection reset".into()],
            ..Default::default()
        };
        let f = findings_for(&[e], &[], &[]);
        assert!(f.iter().any(|x| x.detail.contains("ssh: kex")));
    }

    #[test]
    fn circuits_finding_claims_are_backed_by_evidence() {
        let cs = vec![
            CircuitView {
                label: "tor-circuit-1".into(),
                path_fingerprints: vec!["A".into(), "B".into(), "C".into()],
                ..Default::default()
            },
            CircuitView {
                label: "tor-circuit-2".into(),
                path_fingerprints: vec!["A".into(), "D".into(), "E".into()],
                ..Default::default()
            },
        ];
        let f = findings_for(&[], &cs, &[]);
        let c = f
            .iter()
            .find(|x| x.title.contains("distinct Tor circuit paths"))
            .unwrap();
        assert_eq!(c.severity, "info");
        assert_eq!(c.evidence.len(), 2);
    }

    #[test]
    fn brief_line_fits_a_terminal_and_shows_the_key_hashes() {
        let mut e = EgressView {
            name: "direct".into(),
            kind: "direct".into(),
            ..Default::default()
        };
        e.tls.push(TlsView {
            ours: TlsSummary {
                ja3: "1".repeat(32),
                ja4: "2".repeat(36),
                ..Default::default()
            },
            ..Default::default()
        });
        let line = brief_line(&e);
        assert!(line.contains("ja3="));
        assert!(line.contains("hassh=no ssh") || line.contains("no ssh"));
        assert!(line.len() < 240);
    }

    #[test]
    fn tls_probe_through_the_forwarder_is_confirmed_by_the_lab() {
        let mut lab = Lab::start().unwrap();
        let mut f = Forwarder::start(Upstream::direct()).unwrap();
        let t = tls_probe(
            f.addr,
            "127.0.0.1",
            lab.addrs.tls.port(),
            "stock",
            Duration::from_secs(20),
        )
        .expect("tls probe");
        assert_eq!(t.ours.ja3.len(), 32);
        assert!(t.bytes_sent > 200);
        let snap = lab.snapshot();
        assert_eq!(snap.hellos.len(), 1, "lab saw no hello");
        assert_eq!(snap.hellos[0].summary.ja3, t.ours.ja3);
        f.stop();
        lab.stop();
    }

    #[test]
    fn tls_probe_reports_a_refused_tunnel_without_panicking() {
        let mut f = Forwarder::start(Upstream::direct()).unwrap();
        // nothing listening on this loopback port
        let free = util::free_port().unwrap();
        let e = tls_probe(f.addr, "127.0.0.1", free, "stock", Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("CONNECT"), "unexpected error: {e}");
        f.stop();
    }

    #[test]
    fn ssh_probe_through_the_forwarder_is_confirmed_by_the_lab() {
        let mut lab = Lab::start().unwrap();
        let mut f = Forwarder::start(Upstream::direct()).unwrap();
        let s = ssh_probe(
            f.addr,
            "127.0.0.1",
            lab.addrs.ssh.port(),
            "direct",
            Duration::from_secs(20),
        )
        .expect("ssh probe");
        assert_eq!(s.our_hassh.len(), 32, "hassh should be md5 hex");
        assert!(!s.their_hassh.is_empty());
        let snap = lab.snapshot();
        assert_eq!(snap.ssh.len(), 1, "lab saw no kexinit");
        assert_eq!(snap.ssh[0].hassh, s.our_hassh, "lab must record our HASSH");
        assert_ne!(s.our_hassh, s.their_hassh, "client and server HASSH differ");
        f.stop();
        lab.stop();
    }
}

#[cfg(test)]
#[cfg(test)]
mod circuit_choice_tests {
    use super::*;

    /// A valid 40-hex Tor relay fingerprint derived from a seed byte.
    fn fp40(seed: u8) -> String {
        (0..20)
            .map(|i| format!("{:02x}", seed.wrapping_add(i as u8)))
            .collect()
    }

    fn hop(seed: u8, nick: &str) -> String {
        format!("${}= {}", fp40(seed), nick)
    }

    fn cir(
        id: u32,
        purpose: &str,
        state: &str,
        guard: u8,
        middle: u8,
        exit: u8,
        hops: usize,
    ) -> Circuit {
        let path: Vec<String> = match hops {
            3 => vec![
                hop(guard, "guard"),
                hop(middle, "middle"),
                hop(exit, "exit"),
            ],
            _ => vec![hop(guard, "guard"), hop(middle, "middle")],
        };
        Circuit {
            id,
            purpose: purpose.into(),
            build_type: "4".into(),
            build_flags: String::new(),
            state: state.into(),
            reason: String::new(),
            time_created: String::new(),
            path,
            exit: Some(hop(if hops == 3 { exit } else { middle }, "exit")),
        }
    }

    #[test]
    fn circuit_paths_are_reported_by_nickname() {
        let path = vec![
            "$4D1C9BA70C884135BD0B8DFA61335F7CE0A87EF6~Killix".into(),
            "$D41AFC78224578E5C5B3C26C2E55778037A52C5B=LeClassique".into(),
            "$141C317F74D92DA44FAA072F6BFD0C98DEFF9066=kramse03".into(),
        ];
        assert_eq!(nick_names(&path), ["Killix", "LeClassique", "kramse03"]);
        // an unnamed hop must not silently disappear from the report
        assert_eq!(
            nick_names(&["$4D1C9BA70C884135BD0B8DFA61335F7CE0A87EF6".into()]),
            ["?"]
        );
    }

    #[test]
    fn picks_a_different_exit_relay_each_time() {
        let cs = vec![
            cir(1, "general", "BUILT", 0x10, 0x20, 0x30, 3),
            cir(2, "general", "BUILT", 0x11, 0x21, 0x40, 3),
            cir(3, "general", "BUILT", 0x12, 0x22, 0x50, 3),
        ];
        let mut paths = BTreeSet::new();
        let mut exits = BTreeSet::new();
        let a = pick_circuit(&cs, &paths, &exits).expect("a circuit");
        paths.insert(a.path_fingerprints());
        exits.insert(a.exit_fingerprint().unwrap());
        let b = pick_circuit(&cs, &paths, &exits).expect("a second circuit");
        assert_ne!(
            a.exit_fingerprint(),
            b.exit_fingerprint(),
            "two audited circuits must not share an exit"
        );
    }

    #[test]
    fn prefers_origin_circuits_over_hsdir_lookups() {
        let cs = vec![
            cir(1, "hs_client_hsdir", "BUILT", 0x10, 0x20, 0x30, 3),
            cir(2, "general", "BUILT", 0x11, 0x21, 0x40, 3),
        ];
        let got = pick_circuit(&cs, &BTreeSet::new(), &BTreeSet::new()).unwrap();
        assert_eq!(got.purpose, "general");
    }

    #[test]
    fn unbuilt_and_two_hop_circuits_are_never_chosen() {
        let cs = vec![
            cir(1, "general", "EXTENDED", 0x10, 0x20, 0x30, 3),
            cir(2, "general", "BUILT", 0x11, 0x21, 0x40, 2),
        ];
        assert!(pick_circuit(&cs, &BTreeSet::new(), &BTreeSet::new()).is_none());
    }

    #[test]
    fn service_side_and_directory_circuits_are_never_audited() {
        // Tor's own hidden-service introduction circuit and its directory
        // circuits are BUILT three-hop paths, but our browser never travels
        // them, so they must not be reported as an operator egress.
        let cs = vec![
            cir(1, "hs_service_intro", "BUILT", 0x10, 0x20, 0x30, 3),
            cir(2, "dir_fetch", "BUILT", 0x11, 0x21, 0x40, 3),
            cir(3, "path_bw", "BUILT", 0x12, 0x22, 0x50, 3),
        ];
        assert!(pick_circuit(&cs, &BTreeSet::new(), &BTreeSet::new()).is_none());
    }

    #[test]
    fn an_unnamed_circuit_ranks_below_a_general_one() {
        // tor 0.4.9 omits PURPOSE for some client circuits: such a circuit is
        // still usable, but a `general` one is the better evidence.
        let cs = vec![
            cir(1, "", "BUILT", 0x10, 0x20, 0x30, 3),
            cir(2, "general", "BUILT", 0x11, 0x21, 0x40, 3),
        ];
        let got = pick_circuit(&cs, &BTreeSet::new(), &BTreeSet::new()).expect("a circuit");
        assert_eq!(got.purpose, "general");
    }

    #[test]
    fn falls_back_to_a_fresh_path_when_only_one_exit_exists() {
        // same exit relay, different guard/middle: only the path is fresh
        let cs = vec![
            cir(1, "general", "BUILT", 0x10, 0x20, 0x30, 3),
            cir(2, "general", "BUILT", 0x11, 0x21, 0x30, 3),
        ];
        let mut paths = BTreeSet::new();
        let mut exits = BTreeSet::new();
        let a = pick_circuit(&cs, &paths, &exits).unwrap();
        paths.insert(a.path_fingerprints());
        exits.insert(a.exit_fingerprint().unwrap());
        let b = pick_circuit(&cs, &paths, &exits).expect("fallback to a new path");
        assert_ne!(a.id, b.id);
        assert_eq!(a.exit_fingerprint(), b.exit_fingerprint());
    }
}
