//! Diagnostic: fetch the lab through a hidden service, printing every attempt.
//! Ignored by default (needs the network).

use hardvoy::lab::Lab;
use hardvoy::tor::TorInstance;
use std::time::Duration;

#[test]
#[ignore]
fn fetch_over_hidden_service_prints_every_attempt() {
    let work = std::env::temp_dir().join("hardvoy-tor-live");
    std::fs::create_dir_all(&work).unwrap();
    let lab = Lab::start().unwrap();
    let addrs = lab.addrs.clone();
    let mut tor = TorInstance::start(
        &work,
        &[(80, addrs.http.port()), (443, addrs.tls.port())],
        Duration::from_secs(60),
    )
    .expect("tor starts");
    println!(
        "tor {} onion={} boot {:.1}s",
        tor.version, tor.onion, tor.boot_seconds
    );
    // sanity: the same request bytes work over loopback, so a failure below is
    // about the tor path and not the request
    {
        let wire = hardvoy::httpf::build_request(
            "GET",
            "/identity",
            &[
                ("Host", "127.0.0.1"),
                ("User-Agent", "hardvoy/tor-probe"),
                ("Accept", "*/*"),
                ("Connection", "close"),
            ],
            b"",
        );
        let mut sock = std::net::TcpStream::connect(addrs.http).unwrap();
        std::io::Write::write_all(&mut sock, &wire).unwrap();
        let _ = sock.shutdown(std::net::Shutdown::Write);
        let raw = hardvoy::httpf::read_response(&mut sock);
        let parsed = hardvoy::httpf::parse_response(&raw);
        println!(
            "loopback control request -> status {} ({} bytes), body {} bytes",
            parsed.status,
            raw.len(),
            parsed.body.len()
        );
        assert_eq!(parsed.status, 200, "loopback control request must work");
    }
    for i in 0..6 {
        let t = std::time::Instant::now();
        match tor.fetch("GET", "/identity", None) {
            Ok((status, body)) => println!(
                "attempt {i}: {status} {} bytes in {:.1}s",
                body.len(),
                t.elapsed().as_secs_f64()
            ),
            Err(e) => println!("attempt {i}: {e} (after {:.1}s)", t.elapsed().as_secs_f64()),
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    let snap = lab.snapshot();
    println!(
        "lab saw {} inbound connections and {} requests",
        snap.connects.len(),
        snap.requests.len()
    );
    for c in snap.connects.iter().take(10) {
        println!("  connect: {c:?}");
    }
    for r in snap.requests.iter().take(4) {
        println!(
            "  request: {} {} ({})",
            r.request.method, r.request.path, r.label
        );
    }
    let circuits = tor.circuits().unwrap_or_default();
    println!("{} circuits", circuits.len());
    for c in circuits.iter().take(8) {
        println!(
            "  #{} {} {} {}",
            c.id,
            c.purpose,
            c.state,
            c.path.join(" -> ")
        );
    }
    let log = std::fs::read_to_string(&tor.log_path).unwrap_or_default();
    println!("--- tor log tail ---");
    for l in log.lines().rev().take(25) {
        println!("{l}");
    }
    tor.stop();
}
