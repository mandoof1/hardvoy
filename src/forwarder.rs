//! The egress forwarder: a tiny HTTP/CONNECT proxy that every probe passes
//! through, so a "direct" run and a "Tor" run are the *same* code path with a
//! different upstream. That is what makes the two comparable.
//!
//! Because it sits on the tunnel, the forwarder can also fingerprint the
//! ClientHello the browser produced *before* it leaves, and hardvoy compares
//! that with the hello the lab actually received. If the two differ, something
//! on the path normalised it — a genuinely useful opsec finding.

use crate::httpf::{self, RawRequest};
use crate::lab::{HelloCapture, RequestCapture};
use crate::socks;
use crate::tlsf::{self, ClientHello, TlsSummary};
use crate::util::{now_millis, rfc3339_utc};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamKind {
    /// Straight to the destination.
    Direct,
    /// Through a SOCKS5 proxy (Tor), with remote resolution.
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub kind: UpstreamKind,
    pub proxy: Option<SocketAddr>,
    /// Human readable name used in every capture label, e.g. `tor-9150`.
    pub label: String,
}

impl Upstream {
    pub fn direct() -> Upstream {
        Upstream {
            kind: UpstreamKind::Direct,
            proxy: None,
            label: "direct".into(),
        }
    }

    pub fn socks5(proxy: SocketAddr, label: &str) -> Upstream {
        Upstream {
            kind: UpstreamKind::Socks5,
            proxy: Some(proxy),
            label: label.to_string(),
        }
    }

    pub fn connect(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        match self.kind {
            UpstreamKind::Direct => TcpStream::connect((host, port))
                .inspect(|s| {
                    let _ = s.set_nodelay(true);
                })
                .map_err(|e| format!("direct connect to {host}:{port} failed: {e}")),
            UpstreamKind::Socks5 => {
                let proxy = self
                    .proxy
                    .ok_or_else(|| "socks5 upstream has no proxy address".to_string())?;
                socks::connect(proxy, host, port, None, Duration::from_secs(60))
                    .map_err(|e| format!("socks5 connect to {host}:{port} failed: {e}"))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelLog {
    pub host: String,
    pub port: u16,
    pub seen_at: String,
    pub upstream: String,
}

/// Shared capture sinks: every connection thread writes here.
#[derive(Clone, Default)]
pub struct Sinks {
    pub hellos: Arc<Mutex<Vec<HelloCapture>>>,
    pub requests: Arc<Mutex<Vec<RequestCapture>>>,
    pub tunnels: Arc<Mutex<Vec<TunnelLog>>>,
    pub errors: Arc<Mutex<Vec<String>>>,
}

impl Sinks {
    fn note(&self, msg: String) {
        let mut e = self.errors.lock().unwrap();
        if e.len() < 200 {
            e.push(msg);
        }
    }
}

pub struct Forwarder {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    pub upstream: Upstream,
    sinks: Sinks,
}

impl Forwarder {
    pub fn start(upstream: Upstream) -> std::io::Result<Forwarder> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let sinks = Sinks::default();
        let upstream_for_thread = upstream.clone();
        let sinks_for_thread = sinks.clone();
        let f = Forwarder {
            addr,
            stop: stop.clone(),
            thread: Some(std::thread::spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => {
                            let up = upstream_for_thread.clone();
                            let sinks = sinks_for_thread.clone();
                            std::thread::spawn(move || handle(s, up, sinks));
                        }
                        Err(_) => break,
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            })),
            upstream,
            sinks,
        };
        Ok(f)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn hellos(&self) -> Vec<HelloCapture> {
        self.sinks.hellos.lock().unwrap().clone()
    }

    pub fn requests(&self) -> Vec<RequestCapture> {
        self.sinks.requests.lock().unwrap().clone()
    }

    pub fn tunnels(&self) -> Vec<TunnelLog> {
        self.sinks.tunnels.lock().unwrap().clone()
    }

    pub fn errors(&self) -> Vec<String> {
        self.sinks.errors.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.sinks.hellos.lock().unwrap().clear();
        self.sinks.requests.lock().unwrap().clear();
        self.sinks.tunnels.lock().unwrap().clear();
        self.sinks.errors.lock().unwrap().clear();
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop();
    }
}

fn stamp() -> String {
    rfc3339_utc(now_millis())
}

/// Where the browser sent a request: absolute URI, or origin form + Host.
fn target_of(req: &RawRequest) -> Option<(String, u16, String)> {
    let path = req.path.as_str();
    if let Some(rest) = path.strip_prefix("http://") {
        let (authority, p) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (h, port) = split_authority(authority, 80);
        return Some((h, port, p.to_string()));
    }
    if let Some(rest) = path.strip_prefix("https://") {
        let (authority, p) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (h, port) = split_authority(authority, 443);
        return Some((h, port, p.to_string()));
    }
    let host = req.header("host")?;
    let (h, port) = split_authority(host, 80);
    Some((h, port, path.to_string()))
}

fn split_authority(a: &str, default_port: u16) -> (String, u16) {
    let a = a.trim();
    match a.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default_port))
        }
        _ => (a.to_string(), default_port),
    }
}

fn handle(mut client: TcpStream, up: Upstream, sinks: Sinks) {
    client.set_read_timeout(Some(Duration::from_secs(120))).ok();
    client
        .set_write_timeout(Some(Duration::from_secs(120)))
        .ok();
    let (req, body) = match httpf::read_request(&mut client) {
        Ok(v) => v,
        Err(e) => {
            sinks.note(format!("bad request: {e}"));
            let _ = client.write_all(&httpf::response(
                400,
                "Bad Request",
                "text/plain",
                e.to_string().as_bytes(),
                &[],
            ));
            return;
        }
    };

    if req.method == "CONNECT" {
        let (host, port) = split_authority(&req.path, 443);
        let server = match up.connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                sinks.note(e.clone());
                let _ = client.write_all(&httpf::response(
                    502,
                    "Bad Gateway",
                    "text/plain",
                    e.as_bytes(),
                    &[],
                ));
                return;
            }
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        let _ = client.flush();
        sinks.tunnels.lock().unwrap().push(TunnelLog {
            host: host.clone(),
            port,
            seen_at: stamp(),
            upstream: up.label.clone(),
        });

        let label = format!("forwarder:{}", up.label);
        let mut srv_out = server.try_clone().expect("clone upstream");
        let mut cli_out = client.try_clone().expect("clone client");
        let t = std::thread::spawn(move || {
            let _ = pump(&mut srv_out, &mut cli_out, None, None);
        });

        // client -> upstream, fingerprinting the ClientHello as it passes
        let mut srv_in = server;
        pump(&mut client, &mut srv_in, Some(&sinks.hellos), Some(&label)).ok();
        drop(t);
        return;
    }

    let (host, port, origin_path) = match target_of(&req) {
        Some(v) => v,
        None => {
            sinks.note("request with no usable target".into());
            let _ = client.write_all(&httpf::response(
                400,
                "Bad Request",
                "text/plain",
                b"forwarder: no usable target\n",
                &[],
            ));
            return;
        }
    };
    let mut server = match up.connect(&host, port) {
        Ok(s) => s,
        Err(e) => {
            sinks.note(e.clone());
            let _ = client.write_all(&httpf::response(
                502,
                "Bad Gateway",
                "text/plain",
                e.as_bytes(),
                &[],
            ));
            return;
        }
    };

    // Record the request exactly as the browser sent it (the label carries the
    // egress name), then forward byte-for-byte apart from the request line,
    // which has to become origin-form for an origin server.
    let profile = httpf::profile(&req);
    sinks.requests.lock().unwrap().push(RequestCapture {
        label: format!("forwarder:{}", up.label),
        seen_at: stamp(),
        peer: format!("{host}:{port}"),
        request: req.clone(),
        profile,
    });

    let raw = rewrite_request_line(&req, &origin_path);
    if server.write_all(raw.as_bytes()).is_err() {
        return;
    }
    if !body.is_empty() && server.write_all(&body).is_err() {
        return;
    }
    server.flush().ok();
    let resp = httpf::read_response(&mut server);
    let _ = client.write_all(&resp);
    let _ = client.flush();
    // Close both ends explicitly: a proxy that leaves its side open makes the
    // client wait for bytes that will never come.
    let _ = server.shutdown(std::net::Shutdown::Write);
    let _ = client.shutdown(std::net::Shutdown::Write);
}

/// Replace the request line's target with the origin-form path, keeping every
/// header byte untouched.
fn rewrite_request_line(req: &RawRequest, origin_path: &str) -> String {
    let head = &req.raw_head;
    let mut out = String::new();
    for (i, line) in head.split_inclusive("\r\n").enumerate() {
        if i == 0 {
            out.push_str(&format!("{} {origin_path} {}\r\n", req.method, req.version));
        } else {
            out.push_str(line);
        }
    }
    if !head.ends_with("\r\n\r\n") {
        out.push_str("\r\n\r\n");
    }
    out
}

fn pump(
    from: &mut TcpStream,
    to: &mut TcpStream,
    hellos: Option<&Arc<Mutex<Vec<HelloCapture>>>>,
    label: Option<&str>,
) -> std::io::Result<()> {
    let mut buf = [0u8; 16384];
    let mut acc: Vec<u8> = Vec::new();
    let mut sniffing = hellos.is_some();
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                to.write_all(&buf[..n])?;
                to.flush()?;
                if sniffing {
                    acc.extend_from_slice(&buf[..n]);
                    if acc.len() >= 6 {
                        match ClientHello::from_record_stream(&mut &acc[..]) {
                            Ok((hello, raw)) => {
                                let summary = TlsSummary::compute(&hello, raw.len());
                                if let Some(h) = hellos {
                                    let mut v = h.lock().unwrap();
                                    v.push(HelloCapture {
                                        label: label.unwrap_or("forwarder").to_string(),
                                        peer: "via-forwarder".into(),
                                        seen_at: stamp(),
                                        raw_hex: crate::util::hex(&raw),
                                        summary,
                                    });
                                }
                                sniffing = false;
                            }
                            Err(tlsf::TlsError::Io(_)) => {
                                if acc.len() > 64 * 1024 {
                                    sniffing = false;
                                }
                            }
                            Err(_) => sniffing = false,
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::Lab;
    use std::io::Read;

    fn get_via(proxy: SocketAddr, url_host: &str, url_port: u16, path: &str) -> (String, String) {
        let mut s = TcpStream::connect(proxy).unwrap();
        let req = format!(
            "GET http://{url_host}:{url_port}{path} HTTP/1.1\r\nHost: {url_host}:{url_port}\r\nUser-Agent: hardvoy test\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        (String::from_utf8_lossy(&b).into_owned(), req)
    }

    #[test]
    fn direct_upstream_proxies_a_plain_request() {
        let lab = Lab::start().unwrap();
        let mut f = Forwarder::start(Upstream::direct()).unwrap();
        let (resp, _) = get_via(f.addr, "127.0.0.1", lab.addrs.http.port(), "/identity");
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("\"lab\":\"hardvoy\""));
        let snap = lab.snapshot();
        assert_eq!(snap.requests.len(), 1);
        // the origin saw an origin-form request line
        assert_eq!(snap.requests[0].request.path, "/identity");
        assert_eq!(f.requests().len(), 1);
        assert_eq!(f.requests()[0].label, "forwarder:direct");
        f.clear();
        assert!(f.requests().is_empty());
        f.stop();
    }

    #[test]
    fn header_order_survives_the_forwarder() {
        let lab = Lab::start().unwrap();
        let f = Forwarder::start(Upstream::direct()).unwrap();
        let mut s = TcpStream::connect(f.addr).unwrap();
        let raw = "GET http://127.0.0.1:x/ HTTP/1.1\r\nX-First: 1\r\nHost: 127.0.0.1\r\nX-Second: 2\r\nX-Third: 3\r\n\r\n";
        let raw = raw.replace(":x/", &format!(":{}/", lab.addrs.http.port()));
        s.write_all(raw.as_bytes()).unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        let snap = lab.snapshot();
        assert_eq!(snap.requests.len(), 1);
        let names: Vec<String> = snap.requests[0].request.header_names();
        assert_eq!(names, vec!["X-First", "Host", "X-Second", "X-Third"]);
    }

    #[test]
    fn connect_accepts_the_rfc_space_form_target() {
        let mut lab = Lab::start().unwrap();
        let mut f = Forwarder::start(Upstream::direct()).unwrap();
        let mut s = TcpStream::connect(f.addr).unwrap();
        // RFC 9110 spells the CONNECT target with the port as a separate field
        s.write_all(
            format!(
                "CONNECT 127.0.0.1 {} HTTP/1.1\r\nHost: x\r\n\r\n",
                lab.addrs.http.port()
            )
            .as_bytes(),
        )
        .unwrap();
        s.flush().unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"HTTP");
        let mut rest = [0u8; 40];
        let _ = s.read(&mut rest);
        // and the tunnel really is connected to the lab
        s.write_all(b"GET /identity HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        s.flush().unwrap();
        // read the response without waiting for our own half-close
        let mut body = Vec::new();
        let mut tmp = [0u8; 4096];
        while !body.windows(4).any(|w| w == b"hard") && body.len() < 8192 {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        let _ = s.shutdown(std::net::Shutdown::Write);
        assert!(body.starts_with(b"HTTP/1.1 200"), "tunnel reply: {body:?}");
        let snap = lab.snapshot();
        assert_eq!(snap.requests.len(), 1, "tunnel did not reach the lab");
        assert!(snap.connects.iter().any(|c| c.listener == "http"));
        lab.stop();
        f.stop();
    }

    #[test]
    fn connect_tunnel_carries_tls_and_sniffs_the_hello() {
        let lab = Lab::start().unwrap();
        let f = Forwarder::start(Upstream::direct()).unwrap();
        let mut s = TcpStream::connect(f.addr).unwrap();
        s.write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: x\r\n\r\n",
                lab.addrs.tls.port()
            )
            .as_bytes(),
        )
        .unwrap();
        let mut pre = [0u8; 5];
        s.read_exact(&mut pre).unwrap(); // "HTTP/"
        let mut rest = [0u8; 41];
        let _ = s.read(&mut rest);
        let hello = crate::tlsf::HelloSpec::stock().to_hello();
        s.write_all(&hello.to_bytes()).unwrap();
        let mut alert = [0u8; 7];
        let _ = s.read(&mut alert);
        s.shutdown(std::net::Shutdown::Write).ok();
        assert_eq!(&pre, b"HTTP/");
        // the lab must have seen the ClientHello
        let snap = lab.snapshot();
        assert_eq!(snap.hellos.len(), 1, "lab saw no ClientHello");
        assert_eq!(
            snap.hellos[0].summary.sni.as_deref(),
            Some("hardvoy.invalid")
        );
        // and the forwarder's own thread-local sink saw it client-side
        let hellos = f.hellos();
        assert!(
            hellos
                .iter()
                .any(|h| h.summary.ja3 == snap.hellos[0].summary.ja3),
            "forwarder did not fingerprint the same hello"
        );
    }

    #[test]
    fn socks5_upstream_reaches_the_lab() {
        // stub SOCKS5 that just dials out itself (loopback), to prove the code
        // path is used, without needing Tor in a unit test
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                let mut g = [0u8; 2];
                c.read_exact(&mut g).unwrap();
                let mut m = vec![0u8; g[1] as usize];
                c.read_exact(&mut m).unwrap();
                c.write_all(&[5, 0]).unwrap();
                let mut r = [0u8; 4];
                c.read_exact(&mut r).unwrap();
                let mut hl = [0u8; 1];
                c.read_exact(&mut hl).unwrap();
                let mut host = vec![0u8; hl[0] as usize];
                c.read_exact(&mut host).unwrap();
                let mut port = [0u8; 2];
                c.read_exact(&mut port).unwrap();
                let host = String::from_utf8_lossy(&host).into_owned();
                let port = u16::from_be_bytes(port);
                c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                let _ = host;
                if let Ok(mut out) = TcpStream::connect(("127.0.0.1", port)) {
                    // pump in both directions concurrently, like a real proxy
                    let mut c2 = c.try_clone().unwrap();
                    let mut out2 = out.try_clone().unwrap();
                    let t = std::thread::spawn(move || {
                        let _ = pump(&mut out2, &mut c2, None, None);
                    });
                    let _ = pump(&mut c, &mut out, None, None);
                    let _ = t.join();
                }
            }
        });
        let lab = Lab::start().unwrap();
        let up = Upstream::socks5(proxy, "stub");
        let f = Forwarder::start(up).unwrap();
        let (resp, _) = get_via(
            f.addr,
            "hardvoy-stub.example",
            lab.addrs.http.port(),
            "/identity",
        );
        // The stub resolves the name remotely (as Tor would) and dials the
        // origin, so a successful response proves the socks5 path works.
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("\"lab\":\"hardvoy\""), "{resp}");
        let snap = lab.snapshot();
        assert!(!snap.requests.is_empty(), "origin saw nothing");
    }

    #[test]
    fn unknown_method_and_no_target_are_clean_errors() {
        let f = Forwarder::start(Upstream::direct()).unwrap();
        let mut s = TcpStream::connect(f.addr).unwrap();
        s.write_all(b"NOPE / HTTP/1.1\r\n\r\n").unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        assert!(String::from_utf8_lossy(&b).starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn request_line_rewrite_keeps_headers() {
        let req = httpf::parse_request(
            b"GET http://h:8080/a/b?c=1 HTTP/1.1\r\nHost: h:8080\r\nUser-Agent: ua\r\n\r\n",
        )
        .unwrap();
        let out = rewrite_request_line(&req, "/a/b?c=1");
        assert!(out.starts_with("GET /a/b?c=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: h:8080\r\n"));
        assert!(out.contains("User-Agent: ua\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn target_parsing_handles_forms() {
        let r = httpf::parse_request(
            b"GET http://example.com:8080/x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            target_of(&r).unwrap(),
            ("example.com".into(), 8080, "/x".into())
        );
        let r = httpf::parse_request(b"GET /y HTTP/1.1\r\nHost: other.test\r\n\r\n").unwrap();
        assert_eq!(
            target_of(&r).unwrap(),
            ("other.test".into(), 80, "/y".into())
        );
        let r = httpf::parse_request(b"CONNECT a.test:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(split_authority(&r.path, 443), ("a.test".to_string(), 443));
        let r = httpf::parse_request(b"GET https://s.test/z HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(target_of(&r).unwrap(), ("s.test".into(), 443, "/z".into()));
        let r = httpf::parse_request(b"GET /nohost HTTP/1.1\r\n\r\n").unwrap();
        assert!(target_of(&r).is_none());
    }
}
