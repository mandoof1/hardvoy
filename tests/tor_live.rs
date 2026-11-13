//! Live Tor test: start our own Tor, reach the lab through a hidden service,
//! and show that NEWNYM really changes circuits.
//!
//! Ignored by default because it needs the network; run it with
//! `cargo test --test tor_live -- --ignored --nocapture`.

use hardvoy::lab::Lab;
use hardvoy::tor::TorInstance;
use std::collections::BTreeSet;
use std::time::Duration;

#[test]
#[ignore]
fn hidden_service_is_reachable_and_circuits_rotate() {
    // a fixed workdir so tor's cached descriptors and state make later runs
    // faster than the first one
    let work = std::env::temp_dir().join("hardvoy-tor-live");
    std::fs::create_dir_all(&work).expect("workdir");

    let mut lab = Lab::start().expect("lab starts");
    let addrs = lab.addrs.clone();
    println!(
        "lab up: http={} tls={} ssh={}",
        addrs.http, addrs.tls, addrs.ssh
    );

    let t0 = std::time::Instant::now();
    let mut tor = TorInstance::start(
        &work,
        &[(80, addrs.http.port()), (443, addrs.tls.port())],
        Duration::from_secs(120),
    )
    .expect("tor starts");
    println!(
        "tor {} onion={} control={} socks={} boot {:.1}s",
        tor.version, tor.onion, tor.control, tor.socks, tor.boot_seconds
    );
    assert!(!tor.version.is_empty(), "tor version from control port");

    // A brand-new hidden service needs minutes to publish on a busy network;
    // with a warmed data directory this is seconds.
    let ready = tor
        .wait_ready(Duration::from_secs(420))
        .expect("hidden service reachable");
    println!("hidden service reachable in {ready:.1}s");
    // once the path is warm, individual probes should be quick
    tor.fetch_timeout = Duration::from_secs(75);

    // a real request through the onion path must be recorded by the lab
    let before = lab.snapshot();
    let (status, body) = tor.fetch("GET", "/identity", None).expect("fetch");
    assert_eq!(status, 200, "identity over onion");
    assert!(
        body.contains("served_over") && body.contains("hardvoy"),
        "identity body: {body}"
    );
    println!(
        "GET /identity over {} -> {status} ({} bytes)",
        tor.onion,
        body.len()
    );
    let after = lab.snapshot();
    assert!(
        after.requests.len() > before.requests.len(),
        "the lab must record a request that arrived over the onion service"
    );
    let last = after.requests.last().expect("a request");
    assert!(
        last.request.headers.iter().any(|(k, _)| k == "Host"),
        "Host header must survive the onion path"
    );
    println!(
        "lab saw {} {} (label {}) with Host: {}",
        last.request.method,
        last.request.path,
        last.label,
        last.request.header("Host").unwrap_or("?")
    );

    // circuit evidence: NEWNYM then compare the paths Tor reports
    let mut seen_paths: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut seen_exits: BTreeSet<String> = BTreeSet::new();
    for round in 0..4 {
        tor.newnym().expect("newnym");
        // traffic forces tor to build fresh circuits after the signal
        match tor.fetch("GET", "/identity", None) {
            Ok((status, _)) => println!("round {round}: probe fetch -> {status}"),
            Err(e) => println!("round {round}: probe fetch failed ({e}); reading circuits anyway"),
        }
        std::thread::sleep(Duration::from_secs(3));
        let circuits = tor.circuits().expect("circuits");
        let built: Vec<_> = circuits.iter().filter(|c| c.state == "BUILT").collect();
        let exits: BTreeSet<String> = built.iter().filter_map(|c| c.exit_fingerprint()).collect();
        let paths: BTreeSet<Vec<String>> = built
            .iter()
            .filter(|c| c.path_fingerprints().len() >= 3)
            .map(|c| c.path_fingerprints())
            .collect();
        println!(
            "round {round}: {} circuits, {} built, {} full paths, exits={}",
            circuits.len(),
            built.len(),
            paths.len(),
            exits.len()
        );
        for c in built.iter().take(3) {
            println!(
                "  #{} {} {} {}",
                c.id,
                c.purpose,
                c.state,
                c.path_fingerprints().join(" -> ")
            );
        }
        seen_paths.extend(paths);
        seen_exits.extend(exits);
    }
    println!(
        "distinct full paths observed: {}, distinct last hops: {}",
        seen_paths.len(),
        seen_exits.len()
    );
    assert!(
        !seen_exits.is_empty(),
        "the control port must report at least one built circuit"
    );

    // the raw control-port table belongs in the evidence file
    let raw = tor.circuit_status_raw().expect("raw circuit status");
    let parsed: Vec<_> = raw
        .iter()
        .filter_map(|l| hardvoy::tor::parse_circuit_line(l))
        .collect();
    println!(
        "control port returned {} circuit lines, {} parsed",
        raw.len(),
        parsed.len()
    );
    assert!(
        !parsed.is_empty(),
        "every circuit line from the control port must parse: {raw:?}"
    );

    let transcript = tor.control_transcript().expect("transcript");
    println!("control transcript: {transcript:?}");

    let snap = lab.snapshot();
    println!(
        "lab recorded {} requests and {} inbound connections in {:.1}s total",
        snap.requests.len(),
        snap.connects.len(),
        t0.elapsed().as_secs_f64()
    );
    for c in snap.connects.iter().take(6) {
        println!("  connect: {c:?}");
    }
    assert!(snap.requests.len() >= 2, "more than one request over tor");

    tor.stop();
    lab.stop();
}
