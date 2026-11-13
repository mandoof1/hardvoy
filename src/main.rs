//! hardvoy command line.

use clap::{Args, Parser, Subcommand};
use hardvoy::lab::Lab;
use hardvoy::report::{self, Report};
use hardvoy::scan::{self, Options};
use hardvoy::tlsf::{self, HelloSpec, TlsSummary};
use hardvoy::tor::TorInstance;
use hardvoy::util;
use hardvoy::webrtc;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "hardvoy",
    version,
    about = "Audit the leak surface an operator exposes before touching a target.",
    long_about = "hardvoy measures what an operator's browser and network stack put on the \
wire, per egress path, against a lab it hosts itself on 127.0.0.1. Nothing is sent to a \
third-party host. Reports are JSON plus a self-contained HTML file."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a full audit and write JSON + HTML reports.
    Scan(ScanArgs),
    /// Repeat scans and report the stability rate of every fingerprint.
    Stability(StabilityArgs),
    /// Serve the bundled lab page and its capture endpoints.
    Lab(LabArgs),
    /// Fingerprint our own ClientHello as seen by the lab and the forwarder.
    TlsSelf(TlsSelfArgs),
    /// Parse a ClientHello captured elsewhere (hex or a file of raw bytes).
    TlsParse(TlsParseArgs),
    /// Probe a real SSH server and fingerprint the KEXINIT both ways (HASSH).
    SshProbe(SshProbeArgs),
    /// Audit ICE candidate lines for address leaks.
    WebrtcAudit(WebrtcArgs),
    /// Start Tor, publish a hidden service over the lab, and show circuits.
    TorProbe(TorProbeArgs),
    /// Re-render a report's HTML from its JSON.
    Report(ReportArgs),
    /// Compare fingerprints across several report JSON files.
    Compare(CompareArgs),
    /// Show the versions of the tools this scan depends on.
    Tools,
}

#[derive(Args)]
struct ScanArgs {
    /// Egress path to audit; repeat for each path. direct | tor
    #[arg(long, value_name = "PATH", default_values_t = vec!["direct".to_string()])]
    egress: Vec<String>,
    /// Number of distinct Tor circuits to audit per tor egress
    #[arg(long, default_value_t = 3)]
    circuits: usize,
    /// Firefox profile: stock | leaky | rfp | chromelike
    #[arg(long, default_value = "stock")]
    profile: String,
    /// Lab page mode: leaky | plain | full
    #[arg(long, default_value = "leaky")]
    mode: String,
    /// Firefox binary (defaults to geckodriver's own choice)
    #[arg(long)]
    browser: Option<PathBuf>,
    #[arg(long)]
    geckodriver: Option<PathBuf>,
    /// Where reports are written
    #[arg(long, default_value = "hardvoy-reports")]
    out: PathBuf,
    /// Scratch space for tor, geckodriver logs and screenshots
    #[arg(long, default_value = "/tmp/hardvoy-scan")]
    workdir: PathBuf,
    /// Seconds to wait for the browser probe payload
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Seconds to wait for one wire probe (TLS/SSH through the forwarder)
    #[arg(long, default_value_t = 90)]
    wire_timeout: u64,
    /// Reuse a persistent Tor state dir (guards, descriptors, onion key) so
    /// repeat runs do not pay for bootstrap again
    #[arg(long)]
    tor_state: Option<PathBuf>,
    /// Seconds to wait for Tor bootstrap + hidden-service publication
    #[arg(long, default_value_t = 600)]
    tor_timeout: u64,
    /// Save a PNG screenshot of the lab page for each egress
    #[arg(long)]
    screenshot: bool,
    /// Do not write files (print only)
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct StabilityArgs {
    #[arg(long, value_name = "PATH", default_values_t = vec!["direct".to_string()])]
    egress: Vec<String>,
    /// Profiles to compare, comma separated
    #[arg(long, default_value = "stock,rfp")]
    profiles: String,
    /// Runs per egress per profile (the plan asks for at least 5)
    #[arg(long, default_value_t = 5)]
    runs: usize,
    #[arg(long, default_value = "leaky")]
    mode: String,
    #[arg(long)]
    browser: Option<PathBuf>,
    #[arg(long)]
    geckodriver: Option<PathBuf>,
    #[arg(long, default_value = "hardvoy-reports")]
    out: PathBuf,
    #[arg(long, default_value = "/tmp/hardvoy-stability")]
    workdir: PathBuf,
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    #[arg(long)]
    tor_state: Option<PathBuf>,
    #[arg(long, default_value_t = 600)]
    tor_timeout: u64,
}

#[derive(Args)]
struct LabArgs {
    /// Lab page mode
    #[arg(long, default_value = "leaky")]
    mode: String,
    /// Seconds to serve (0 = until Ctrl-C)
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    /// Print what the lab captured when the time is up
    #[arg(long)]
    dump: bool,
    /// Also start an HTTP/CONNECT forwarder in front of the lab, and print its
    /// address, so a browser can be pointed at it by hand
    #[arg(long)]
    proxy: bool,
}

#[derive(Args)]
struct TlsSelfArgs {
    /// stock | greased | both
    #[arg(long, default_value = "both")]
    variant: String,
    /// Route through this SOCKS5 proxy (for example a Tor SOCKS port)
    #[arg(long)]
    through_socks: Option<String>,
}

#[derive(Args)]
struct TlsParseArgs {
    /// Hex bytes of a TLS record containing a ClientHello
    #[arg(long, conflicts_with = "file")]
    hex: Option<String>,
    /// File with the raw bytes (for example from tshark -x output piping)
    #[arg(long, conflicts_with = "hex")]
    file: Option<PathBuf>,
}

#[derive(Args)]
struct SshProbeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// Which KEXINIT profile to send: openssh9.9 | minimal | default
    #[arg(long, default_value = "openssh9.9")]
    spec: String,
}

#[derive(Args)]
struct WebrtcArgs {
    /// File with one ICE candidate per line
    #[arg(long)]
    file: PathBuf,
    /// Treat the egress as anonymous (a Tor path), which changes the verdict
    #[arg(long)]
    anonymous_egress: bool,
}

#[derive(Args)]
struct TorProbeArgs {
    /// NEWNYM rounds
    #[arg(long, default_value_t = 3)]
    rounds: usize,
    #[arg(long, default_value = "/tmp/hardvoy-tor-probe")]
    workdir: PathBuf,
    /// Seconds to wait for the hidden service
    #[arg(long, default_value_t = 600)]
    timeout: u64,
}

#[derive(Args)]
struct ReportArgs {
    /// A report JSON written by `hardvoy scan`
    #[arg(long)]
    json: PathBuf,
    /// Output HTML (defaults next to the JSON)
    #[arg(long)]
    html: Option<PathBuf>,
}

#[derive(Args)]
struct CompareArgs {
    /// Report JSON files
    #[arg(value_name = "JSON")]
    files: Vec<PathBuf>,
}

fn main() {
    // A CLI that only writes to a pipe should die quietly when the reader goes
    // away (`hardvoy compare | head -3`), not panic inside println!.
    #[cfg(unix)]
    unsafe {
        extern "C" {
            fn signal(sig: i32, handler: usize) -> usize;
        }
        const SIGPIPE: i32 = 13;
        const SIG_DFL: usize = 0;
        let _ = signal(SIGPIPE, SIG_DFL);
    }

    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Scan(a) => cmd_scan(a),
        Cmd::Stability(a) => cmd_stability(a),
        Cmd::Lab(a) => cmd_lab(a),
        Cmd::TlsSelf(a) => cmd_tls_self(a),
        Cmd::TlsParse(a) => cmd_tls_parse(a),
        Cmd::SshProbe(a) => cmd_ssh_probe(a),
        Cmd::WebrtcAudit(a) => cmd_webrtc_audit(a),
        Cmd::TorProbe(a) => cmd_tor_probe(a),
        Cmd::Report(a) => cmd_report(a),
        Cmd::Compare(a) => cmd_compare(a),
        Cmd::Tools => {
            for (k, v) in scan::tool_inventory() {
                println!("{k}\t{v}");
            }
            0
        }
    };
    std::process::exit(code);
}

fn opts_from(a: &ScanArgs) -> Options {
    Options {
        egresses: a.egress.clone(),
        circuits: a.circuits,
        profile: a.profile.clone(),
        browser: a.browser.clone(),
        geckodriver: a.geckodriver.clone(),
        mode: a.mode.clone(),
        workdir: a.workdir.clone(),
        tor_state: a.tor_state.clone(),
        tor_timeout: Duration::from_secs(a.tor_timeout),
        probe_timeout: Duration::from_secs(a.timeout),
        wire_timeout: Duration::from_secs(a.wire_timeout),
        screenshot: a.screenshot,
    }
}

fn cmd_scan(a: ScanArgs) -> i32 {
    let o = opts_from(&a);
    println!(
        "hardvoy {} — scan egress=[{}] circuits={} profile={} mode={}",
        env!("CARGO_PKG_VERSION"),
        a.egress.join(","),
        a.circuits,
        a.profile,
        a.mode
    );
    let t0 = Instant::now();
    let r = match scan::scan(&o) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e}");
            return 2;
        }
    };
    print_summary(&r);
    if a.dry_run {
        println!("\ndry run: nothing written");
        return 0;
    }
    if let Err(e) = write_report(&a.out, &r) {
        eprintln!("write failed: {e}");
        return 2;
    }
    println!(
        "\n{} findings, {:.1}s; wrote {}.json and .html for report {}",
        r.findings.len(),
        t0.elapsed().as_secs_f64(),
        a.out.join(format!("report-{}", r.id)).display(),
        r.id
    );
    0
}

fn write_report(out: &PathBuf, r: &Report) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let base = out.join(format!("report-{}", r.id));
    let json = format!("{}.json", base.display());
    let html = format!("{}.html", base.display());
    std::fs::write(&json, serde_json::to_string_pretty(r).unwrap())
        .map_err(|e| json.clone() + ": " + &e.to_string())?;
    std::fs::write(&html, report::html(r)).map_err(|e| html.clone() + ": " + &e.to_string())?;
    Ok(())
}

fn print_summary(r: &Report) {
    println!("\n== egress paths ==");
    for e in &r.egresses {
        println!("{}", scan::brief_line(e));
    }
    println!("\n== findings ==");
    for f in &r.findings {
        println!(
            "[{:<8}] {:<4} {} — {}",
            f.severity.to_uppercase(),
            f.id,
            f.title,
            truncate(&f.detail, 150)
        );
    }
    println!("\n== correlation ==");
    println!(
        "risk {} — {}",
        r.correlation.risk,
        truncate(&r.correlation.explanation, 200)
    );
    for (k, v) in &r.correlation.shared {
        println!("  same    {k} = {v}");
    }
    for (k, v) in &r.correlation.divergent {
        println!("  differs {k} = {}", v.join(" | "));
    }
    if !r.circuits.is_empty() {
        println!("\n== tor circuits ==");
        for c in &r.circuits {
            println!(
                "{}  {} {}  {}",
                c.label,
                c.purpose,
                c.state,
                c.path_nicks
                    .iter()
                    .zip(c.path_fingerprints.iter())
                    .map(|(n, f)| format!("{n}({})", &f[..8]))
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
        }
    }
    for n in &r.notes {
        println!("note: {n}");
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

/// Repeat the same scan for each profile and report how stable each
/// fingerprint is, run to run, and whether profiles differ.
fn cmd_stability(a: StabilityArgs) -> i32 {
    let profiles: Vec<String> = a
        .profiles
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    println!(
        "hardvoy stability: {} runs × {} profile(s) × egress=[{}]",
        a.runs,
        profiles.len(),
        a.egress.join(",")
    );
    // (profile, egress) -> run -> fingerprint -> hash
    let mut table: BTreeMap<(String, String), Vec<BTreeMap<String, String>>> = BTreeMap::new();
    let mut errors: Vec<String> = Vec::new();
    for profile in &profiles {
        for run in 0..a.runs {
            let o = Options {
                egresses: a.egress.clone(),
                circuits: if a.egress.iter().any(|e| e == "tor") {
                    1
                } else {
                    0
                }
                .max(1),
                profile: profile.clone(),
                browser: a.browser.clone(),
                geckodriver: a.geckodriver.clone(),
                mode: a.mode.clone(),
                workdir: a.workdir.clone(),
                tor_state: a.tor_state.clone(),
                tor_timeout: Duration::from_secs(a.tor_timeout),
                probe_timeout: Duration::from_secs(a.timeout),
                wire_timeout: Duration::from_secs(90),
                screenshot: false,
            };
            let r = match scan::scan(&o) {
                Ok(r) => r,
                Err(e) => {
                    errors.push(format!("{profile} run {run}: {e}"));
                    continue;
                }
            };
            for e in &r.egresses {
                let mut row: BTreeMap<String, String> = BTreeMap::new();
                for name in report::COMPARED {
                    if let Some(h) = report::fingerprint_of(e, name) {
                        row.insert(name.to_string(), h);
                    }
                }
                table
                    .entry((profile.clone(), e.name.clone()))
                    .or_default()
                    .push(row);
            }
            println!(
                "  {profile} run {run}: {} fingerprints, {} findings, {:.1}s",
                table
                    .values()
                    .map(|v| v.last().map(|r| r.len()).unwrap_or(0))
                    .max()
                    .unwrap_or(0),
                r.findings.len(),
                r.timings.get("scan_total").copied().unwrap_or(0.0)
            );
            for e in &r.egresses {
                write_stability_report(&a.out, &r, e);
            }
        }
    }

    // stability: identical in every run of the same (profile, egress)
    println!("\n== stability across runs ==");
    println!("| profile | egress | fingerprint | runs | distinct | stable | rate |");
    println!("|---|---|---|---|---|---|---|");
    let mut overall = (0usize, 0usize);
    for ((profile, egress), rows) in &table {
        for name in report::COMPARED {
            let vals: Vec<String> = rows.iter().filter_map(|r| r.get(name).cloned()).collect();
            if vals.is_empty() {
                continue;
            }
            let uniq: std::collections::BTreeSet<&String> = vals.iter().collect();
            let distinct = uniq.len();
            let stable = distinct == 1;
            let rate = if stable {
                100
            } else {
                100 / distinct.min(vals.len())
            };
            overall.0 += if stable { 1 } else { 0 };
            overall.1 += 1;
            println!(
                "| {profile} | {egress} | {name} | {} | {distinct} | {} | {rate}% |",
                vals.len(),
                if stable { "yes" } else { "no" }
            );
        }
    }
    println!(
        "\n{}/{} fingerprints identical across every run of the same profile and egress",
        overall.0, overall.1
    );

    // do profiles differ? that is what makes a profile switch worth doing
    println!("\n== profile differences (same egress) ==");
    println!("| egress | fingerprint | profiles agree | first hash per profile |");
    println!("|---|---|---|---|");
    let mut egrs: std::collections::BTreeSet<String> = Default::default();
    // the same egress is named `direct`, `direct/rfp`, `direct/leaky` depending
    // on the browser profile, so profiles are compared on the base egress only
    let base_of = |e: &str| e.split('/').next().unwrap_or(e).to_string();
    for (_, e) in table.keys() {
        egrs.insert(base_of(e));
    }
    let mut agree = (0usize, 0usize);
    for e in &egrs {
        for name in report::COMPARED {
            let mut per_profile: BTreeMap<String, String> = BTreeMap::new();
            for (profile, egress) in table.keys() {
                if base_of(egress) != *e {
                    continue;
                }
                if let Some(row) = table
                    .get(&(profile.clone(), egress.clone()))
                    .and_then(|rows| rows.first())
                {
                    if let Some(h) = row.get(name) {
                        per_profile.insert(profile.clone(), h.clone());
                    }
                }
            }
            if per_profile.len() < 2 {
                continue;
            }
            let uniq: std::collections::BTreeSet<&String> = per_profile.values().collect();
            agree.1 += 1;
            if uniq.len() == 1 {
                agree.0 += 1;
            }
            let detail: Vec<String> = per_profile
                .iter()
                .map(|(p, h)| format!("{p}={}", &h[..8.min(h.len())]))
                .collect();
            println!(
                "| {e} | {name} | {} | {} |",
                if uniq.len() == 1 {
                    "identical"
                } else {
                    "DIFFERENT"
                },
                detail.join(", ")
            );
        }
    }
    println!(
        "\n{}/{} fingerprint families identical across every browser profile on the same egress",
        agree.0, agree.1
    );
    if !errors.is_empty() {
        println!("\nerrors:");
        for e in &errors {
            println!("  {e}");
        }
    }
    let json = a.out.join(format!("stability-{}.json", util::now_secs()));
    let _ = std::fs::create_dir_all(&a.out);
    let dump = serde_json::json!({
        "runs": a.runs,
        "profiles": profiles,
        "egresses": a.egress,
        "table": table.iter().map(|((p, e), rows)| serde_json::json!({"profile":p,"egress":e,"runs":rows})).collect::<Vec<_>>(),
        "stable_count": overall.0,
        "measured_count": overall.1,
        "errors": errors,
    });
    if let Err(e) = std::fs::write(&json, serde_json::to_string_pretty(&dump).unwrap()) {
        eprintln!("write {}: {e}", json.display());
    } else {
        println!("wrote {}", json.display());
    }
    if errors.is_empty() {
        0
    } else {
        1
    }
}

fn write_stability_report(out: &PathBuf, r: &Report, e: &hardvoy::report::EgressView) {
    // one report file per run keeps the raw evidence of every run
    let mut one = r.clone();
    one.egresses = vec![e.clone()];
    one.correlation = report::correlate(&one.egresses);
    one.id = format!("{}-{}", r.id, e.name.replace('/', "-"));
    let _ = write_report(out, &one);
}

fn cmd_lab(a: LabArgs) -> i32 {
    let mut lab = match Lab::start() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lab: {e}");
            return 2;
        }
    };
    let addrs = lab.addrs.clone();
    println!("hardvoy lab on 127.0.0.1 (mode {})", a.mode);
    println!("  page    http://{}/?run=demo&mode={}", addrs.http, a.mode);
    println!("  tls     {} (ClientHello sniffer)", addrs.tls);
    println!("  ssh     {} (KEXINIT/HASSH sniffer)", addrs.ssh);
    println!("  identity http://{}/identity", addrs.http);
    let mut fwd = if a.proxy {
        match hardvoy::forwarder::Forwarder::start(hardvoy::forwarder::Upstream::direct()) {
            Ok(f) => {
                println!(
                    "  forwarder (http proxy) {}  e.g. curl -x http://{} {}/",
                    f.addr, f.addr, addrs.http
                );
                Some(f)
            }
            Err(e) => {
                eprintln!("forwarder: {e}");
                None
            }
        }
    } else {
        None
    };
    let stop = a.seconds;
    let t0 = Instant::now();
    while stop == 0 || t0.elapsed().as_secs() < stop {
        std::thread::sleep(Duration::from_millis(500));
    }
    let snap = lab.snapshot();
    println!(
        "\ncaptured {} requests, {} ClientHellos, {} KEXINITs, {} probe payloads",
        snap.requests.len(),
        snap.hellos.len(),
        snap.ssh.len(),
        snap.collected.len()
    );
    if a.dump {
        println!(
            "{}",
            serde_json::to_string_pretty(&snap).unwrap_or_default()
        );
    }
    if let Some(mut f) = fwd.take() {
        f.stop();
    }
    lab.stop();
    0
}

fn cmd_tls_self(a: TlsSelfArgs) -> i32 {
    let mut lab = match Lab::start() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lab: {e}");
            return 2;
        }
    };
    let up = match &a.through_socks {
        Some(p) => {
            let addr = match p.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("bad --through-socks {p}: {e}");
                    return 2;
                }
            };
            hardvoy::forwarder::Upstream::socks5(addr, "socks5")
        }
        None => hardvoy::forwarder::Upstream::direct(),
    };
    let mut f = match hardvoy::forwarder::Forwarder::start(up) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("forwarder: {e}");
            return 2;
        }
    };
    let variants: Vec<&str> = match a.variant.as_str() {
        "both" => vec!["stock", "greased"],
        v => vec![v],
    };
    for v in variants {
        lab.clear();
        f.clear();
        let spec = match v {
            "greased" => HelloSpec::stock().greased(),
            _ => HelloSpec::stock(),
        };
        let hello = spec.to_hello();
        let wire = hello.to_bytes();
        let ours = TlsSummary::compute(&hello, wire.len());
        let mut s = match std::net::TcpStream::connect(f.addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("connect forwarder: {e}");
                return 2;
            }
        };
        s.set_read_timeout(Some(Duration::from_secs(20))).ok();
        if let Err(e) = s.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
                lab.addrs.tls.port()
            )
            .as_bytes(),
        ) {
            eprintln!("connect: {e}");
            return 2;
        }
        let head = match read_proxy_head(&mut s) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("proxy head: {e}");
                return 2;
            }
        };
        if !head.contains("200") {
            eprintln!("proxy refused: {}", head.trim());
            return 2;
        }
        s.write_all(&wire).ok();
        let mut reply = [0u8; 64];
        let n = s.read(&mut reply).unwrap_or(0);
        let _ = s.shutdown(std::net::Shutdown::Write);
        let _ = n;
        let hellos = f.hellos();
        let snap = lab.snapshot();
        let lab_seen = snap.hellos.iter().find(|h| h.summary.ja3 == ours.ja3);
        let fwd_seen = hellos.iter().find(|h| h.summary.ja3 == ours.ja3);
        println!("== {v} ClientHello ({} bytes) ==", wire.len());
        println!("  JA3      {}", ours.ja3);
        println!("  JA3 str  {}", ours.ja3_string);
        println!("  JA4      {}", ours.ja4);
        println!("  JA4 raw  {}", ours.ja4_raw);
        println!("  wire     {}", ours.wire_summary);
        println!("  GREASE   {}", ours.grease_present);
        println!("  versions {:?}", ours.supported_versions);
        println!("  ciphers  {}", ours.ciphers.len());
        println!("  exts     {}", ours.extensions.len());
        println!("  sni      {:?}", ours.sni);
        println!(
            "  lab saw the same hello: {}   forwarder saw the same hello: {}",
            lab_seen.is_some(),
            fwd_seen.is_some()
        );
        if lab_seen.is_none() || fwd_seen.is_none() {
            println!(
                "  lab hellos: {:?}",
                snap.hellos
                    .iter()
                    .map(|h| h.summary.ja3.clone())
                    .collect::<Vec<_>>()
            );
            println!(
                "  forwarder hellos: {:?}",
                hellos
                    .iter()
                    .map(|h| h.summary.ja3.clone())
                    .collect::<Vec<_>>()
            );
            f.stop();
            lab.stop();
            return 1;
        }
    }
    f.stop();
    lab.stop();
    0
}

fn cmd_tls_parse(a: TlsParseArgs) -> i32 {
    let bytes = match (&a.hex, &a.file) {
        (Some(h), _) => tlsf::from_hex(h),
        (None, Some(p)) => match std::fs::read(p) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{}: {e}", p.display());
                return 2;
            }
        },
        _ => {
            eprintln!("need --hex or --file");
            return 2;
        }
    };
    let mut cur = std::io::Cursor::new(bytes);
    match tlsf::ClientHello::from_record_stream(&mut cur) {
        Ok((hello, used)) => {
            let s = TlsSummary::compute(&hello, used.len());
            println!("JA3      {}", s.ja3);
            println!("JA3 str  {}", s.ja3_string);
            println!("JA4      {}", s.ja4);
            println!("JA4 raw  {}", s.ja4_raw);
            println!("wire     {}", s.wire_summary);
            println!("GREASE   {}", s.grease_present);
            println!("versions {:?}", s.supported_versions);
            println!("sni      {:?}", s.sni);
            println!("alpn     {:?}", s.alpn);
            0
        }
        Err(e) => {
            eprintln!("not a ClientHello: {e}");
            1
        }
    }
}

fn cmd_ssh_probe(a: SshProbeArgs) -> i32 {
    let sock = match std::net::TcpStream::connect((a.host.as_str(), a.port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect {}:{}: {e}", a.host, a.port);
            return 2;
        }
    };
    match hardvoy::sshf::exchange_with_timeout(sock, &a.spec, Duration::from_secs(15)) {
        Ok(ex) => {
            println!("banner        {}", ex.their_banner);
            println!("our HASSH     {}", ex.our_hassh);
            println!("their HASSH   {}", ex.their_hassh);
            println!("their kex     {}", ex.their_kex.kex_algorithms.join(","));
            println!("their ciphers {}", ex.their_kex.encryption_c2s.join(","));
            println!("their macs    {}", ex.their_kex.mac_c2s.join(","));
            0
        }
        Err(e) => {
            eprintln!("kex failed: {e}");
            1
        }
    }
}

/// Read a proxy response head (`...\r\n\r\n`).
fn read_proxy_head<R: Read>(r: &mut R) -> Result<String, String> {
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
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn cmd_webrtc_audit(a: WebrtcArgs) -> i32 {
    let text = match std::fs::read_to_string(&a.file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: {e}", a.file.display());
            return 2;
        }
    };
    let lines: Vec<String> = text.lines().map(String::from).collect();
    let audit = webrtc::audit(&lines, a.anonymous_egress);
    println!("severity {}", audit.severity);
    println!(
        "candidates {}  mdns-only {}",
        audit.candidate_count, audit.mdns_only
    );
    for c in &audit.candidates {
        println!("  {} [{} {}]", c.raw, c.address_class, c.kind);
    }
    for f in &audit.findings {
        println!("  finding: {f}");
    }
    if audit.leaked_private.is_empty() && audit.leaked_public.is_empty() {
        println!("no address leak");
    }
    match audit.severity.as_str() {
        "high" => 1,
        _ => 0,
    }
}

fn cmd_tor_probe(a: TorProbeArgs) -> i32 {
    let mut lab = match Lab::start() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lab: {e}");
            return 2;
        }
    };
    let addrs = lab.addrs.clone();
    std::fs::create_dir_all(&a.workdir).ok();
    let mut tor = match TorInstance::start(
        &a.workdir,
        &[
            (80, addrs.http.port()),
            (443, addrs.tls.port()),
            (22, addrs.ssh.port()),
        ],
        Duration::from_secs(90),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tor: {e}");
            return 2;
        }
    };
    println!(
        "tor {} onion={} socks={} control={} boot {:.1}s",
        tor.version, tor.onion, tor.socks, tor.control, tor.boot_seconds
    );
    match tor.wait_ready(Duration::from_secs(a.timeout)) {
        Ok(s) => println!("hidden service reachable in {s:.1}s"),
        Err(e) => {
            eprintln!("{e}");
            tor.stop();
            lab.stop();
            return 1;
        }
    }
    match tor.fetch("GET", "/identity", None) {
        Ok((st, body)) => println!("GET /identity over onion -> {st} ({} bytes)", body.len()),
        Err(e) => println!("fetch failed: {e}"),
    }
    let mut seen: std::collections::BTreeSet<Vec<String>> = Default::default();
    for round in 0..a.rounds.max(1) {
        if let Err(e) = tor.newnym() {
            eprintln!("newnym: {e}");
        }
        let _ = tor.fetch("GET", "/identity", None);
        std::thread::sleep(Duration::from_secs(2));
        let cs = tor.circuits().unwrap_or_default();
        for c in cs
            .iter()
            .filter(|c| c.state == "BUILT" && c.path_fingerprints().len() >= 3)
        {
            let fp = c.path_fingerprints();
            if seen.insert(fp.clone()) {
                println!(
                    "round {round} circuit {}: {} {} {}",
                    c.id,
                    c.purpose,
                    c.state,
                    hardvoy::scan::join_path(&fp)
                );
            }
        }
    }
    println!("{} distinct circuit paths", seen.len());
    tor.stop();
    lab.stop();
    if seen.is_empty() {
        1
    } else {
        0
    }
}

fn cmd_report(a: ReportArgs) -> i32 {
    match scan::html_from_json(&a.json) {
        Ok(h) => {
            let out = a
                .html
                .clone()
                .unwrap_or_else(|| a.json.with_extension("html"));
            let len = h.len();
            match std::fs::write(&out, h) {
                Ok(()) => {
                    println!("wrote {} ({} bytes)", out.display(), len);
                    0
                }
                Err(e) => {
                    eprintln!("{}: {e}", out.display());
                    2
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

fn cmd_compare(a: CompareArgs) -> i32 {
    let mut reports: Vec<Report> = Vec::new();
    for f in &a.files {
        let text = match std::fs::read_to_string(f) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{}: {e}", f.display());
                return 2;
            }
        };
        match serde_json::from_str::<Report>(&text) {
            Ok(r) => reports.push(r),
            Err(e) => {
                eprintln!("{}: not a hardvoy report: {e}", f.display());
                return 2;
            }
        }
    }
    let mut cols: Vec<(String, hardvoy::report::EgressView)> = Vec::new();
    for r in &reports {
        for e in &r.egresses {
            cols.push((r.id.clone(), e.clone()));
        }
    }
    println!("fingerprints across {} report(s)", reports.len());
    print!("| fingerprint |");
    for (id, e) in &cols {
        print!(" {id}/{name} |", name = e.name);
    }
    println!();
    print!("|---|");
    for _ in &cols {
        print!("---|");
    }
    println!();
    for name in report::COMPARED {
        print!("| {name} |");
        let mut vals = Vec::new();
        for (_, e) in &cols {
            let h = report::fingerprint_of(e, name);
            print!(" {} |", h.unwrap_or_else(|| "-".into()));
            vals.push(report::fingerprint_of(e, name));
        }
        let present: Vec<String> = vals.iter().flatten().cloned().collect();
        if present.len() > 1 {
            let uniq: std::collections::BTreeSet<String> = present.into_iter().collect();
            if uniq.len() > 1 {
                println!("  ^ differs");
            } else {
                println!("  ^ same");
            }
        } else {
            println!();
        }
    }
    0
}
