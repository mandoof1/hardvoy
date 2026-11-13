//! hardvoy's own lab: three loopback listeners that record what a browser
//! actually puts on the wire.
//!
//! * HTTP/1.1 — serves the probe page and collects its POSTed payload, while
//!   capturing the raw request (header order included)
//! * TLS sniffer — reads only the ClientHello, fingerprints it, then answers
//!   with a TLS alert. No certificate is involved, so the hello a browser
//!   produces is captured exactly as sent.
//! * SSH KEXINIT sniffer — reads the banner and KEXINIT, fingerprints them,
//!   answers with our own KEXINIT, then closes.
//!
//! The lab never phones anything third-party, so a scan is reproducible and
//! works offline.

use crate::httpf::{self, RawRequest};
use crate::sshf::{self, KexInit};
use crate::tlsf::{self, TlsSummary};
use crate::util::{now_millis, rfc3339_utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloCapture {
    pub label: String,
    pub peer: String,
    pub seen_at: String,
    pub raw_hex: String,
    pub summary: TlsSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshCapture {
    pub label: String,
    pub peer: String,
    pub seen_at: String,
    pub banner: String,
    pub hassh: String,
    pub kex: KexInit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCapture {
    pub label: String,
    pub seen_at: String,
    pub peer: String,
    pub request: RawRequest,
    pub profile: httpf::HttpProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collected {
    pub run: String,
    pub seen_at: String,
    pub bytes: usize,
    pub payload: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabSnapshot {
    pub requests: Vec<RequestCapture>,
    pub hellos: Vec<HelloCapture>,
    pub ssh: Vec<SshCapture>,
    pub collected: Vec<Collected>,
    pub connects: Vec<ConnectLog>,
}

/// One inbound connection observed by the lab, with the address the peer
/// presented. This is how a hidden-service connection is distinguished from a
/// loopback one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectLog {
    pub listener: String,
    pub peer: String,
    pub seen_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabAddrs {
    pub http: SocketAddr,
    pub tls: SocketAddr,
    pub ssh: SocketAddr,
}

#[derive(Clone, Default)]
struct State {
    requests: Vec<RequestCapture>,
    hellos: Vec<HelloCapture>,
    ssh: Vec<SshCapture>,
    collected: Vec<Collected>,
    connects: Vec<ConnectLog>,
}

pub struct Lab {
    pub addrs: LabAddrs,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    state: Arc<Mutex<State>>,
}

impl Lab {
    /// Bind three ephemeral loopback listeners and start serving.
    pub fn start() -> std::io::Result<Lab> {
        let http_l = TcpListener::bind(("127.0.0.1", 0))?;
        let tls_l = TcpListener::bind(("127.0.0.1", 0))?;
        let ssh_l = TcpListener::bind(("127.0.0.1", 0))?;
        let addrs = LabAddrs {
            http: http_l.local_addr()?,
            tls: tls_l.local_addr()?,
            ssh: ssh_l.local_addr()?,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(State::default()));
        let mut threads = Vec::new();
        for (name, listener, kind) in [
            ("http", http_l, "http"),
            ("tls", tls_l, "tls"),
            ("ssh", ssh_l, "ssh"),
        ] {
            let stop = stop.clone();
            let state = state.clone();
            threads.push(std::thread::spawn(move || {
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => {
                            let state = state.clone();
                            std::thread::spawn(move || {
                                let peer = s
                                    .peer_addr()
                                    .map(|a| a.to_string())
                                    .unwrap_or_else(|_| "?".into());
                                log_connect(&state, name, &peer);
                                match kind {
                                    "http" => serve_http(s, state),
                                    "tls" => serve_tls(s, state),
                                    _ => serve_ssh(s, state),
                                }
                            });
                        }
                        Err(_) => break,
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }));
        }
        Ok(Lab {
            addrs,
            stop,
            threads,
            state,
        })
    }

    /// Stop accepting and drop the worker threads.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for addr in [self.addrs.http, self.addrs.tls, self.addrs.ssh] {
            let _ = TcpStream::connect(addr); // wake the accept loop
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    pub fn snapshot(&self) -> LabSnapshot {
        let s = self.state.lock().expect("lab state lock");
        LabSnapshot {
            requests: s.requests.clone(),
            hellos: s.hellos.clone(),
            ssh: s.ssh.clone(),
            collected: s.collected.clone(),
            connects: s.connects.clone(),
        }
    }

    pub fn clear(&self) {
        let mut s = self.state.lock().expect("lab state lock");
        s.requests.clear();
        s.hellos.clear();
        s.ssh.clear();
        s.collected.clear();
        s.connects.clear();
    }

    /// The payload the probe page POSTed for `run`, if it has arrived.
    pub fn collected_for(&self, run: &str) -> Option<Collected> {
        let s = self.state.lock().expect("lab state lock");
        s.collected.iter().rev().find(|c| c.run == run).cloned()
    }

    pub fn hellos_since(&self, n: usize) -> Vec<HelloCapture> {
        let s = self.state.lock().expect("lab state lock");
        s.hellos.iter().skip(n).cloned().collect()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.stop();
    }
}

fn stamp() -> String {
    rfc3339_utc(now_millis())
}

fn log_connect(state: &Arc<Mutex<State>>, listener: &str, peer: &str) {
    let mut s = state.lock().expect("lab state lock");
    s.connects.push(ConnectLog {
        listener: listener.to_string(),
        peer: peer.to_string(),
        seen_at: stamp(),
    });
}

// ---------------------------------------------------------------------------
// HTTP

fn serve_http(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let (req, body) = match httpf::read_request(&mut stream) {
        Ok(v) => v,
        Err(_) => {
            let _ = stream.write_all(&httpf::response(
                400,
                "Bad Request",
                "text/plain",
                b"hardvoy lab: malformed request\n",
                &[],
            ));
            return;
        }
    };
    let profile = httpf::profile(&req);
    {
        let mut s = state.lock().expect("lab state lock");
        s.requests.push(RequestCapture {
            label: "http".into(),
            seen_at: stamp(),
            peer: peer.clone(),
            request: req.clone(),
            profile: profile.clone(),
        });
    }

    let path = req.path.split('?').next().unwrap_or("/").to_string();
    let query: Vec<(String, String)> = req
        .path
        .split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let get = |k: &str| {
        query
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, b)| b.clone())
            .unwrap_or_default()
    };

    let (status, reason, ctype, payload, extra) = match path.as_str() {
        "/" => (
            200,
            "OK",
            "text/html; charset=utf-8",
            crate::page::page_html(&get("run"), &get("mode")).into_bytes(),
            vec![],
        ),
        "/lab.js" => (
            200,
            "OK",
            "application/javascript; charset=utf-8",
            crate::page::probe_js().into_bytes(),
            vec![],
        ),
        "/identity" => (
            200,
            "OK",
            "application/json",
            serde_json::to_vec(&serde_json::json!({
                "lab": "hardvoy",
                "version": env!("CARGO_PKG_VERSION"),
                "seen_at": stamp(),
                "peer": peer,
                "served_over": "cleartext-http",
            }))
            .unwrap_or_default(),
            vec![],
        ),
        "/headers" => (
            200,
            "OK",
            "application/json",
            serde_json::to_vec(&profile).unwrap_or_default(),
            vec![],
        ),
        "/collect" => {
            let run = get("run");
            let payload: Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
                    serde_json::json!({"hardvoy_parse_error": e.to_string(), "raw_len": body.len()})
                });
            {
                let mut s = state.lock().expect("lab state lock");
                s.collected.push(Collected {
                    run: run.clone(),
                    seen_at: stamp(),
                    bytes: body.len(),
                    payload: payload.clone(),
                });
            }
            (
                200,
                "OK",
                "application/json",
                serde_json::to_vec(&serde_json::json!({"ok": true, "run": run}))
                    .unwrap_or_default(),
                vec![],
            )
        }
        "/clear" => {
            let mut s = state.lock().expect("lab state lock");
            s.requests.clear();
            s.hellos.clear();
            s.ssh.clear();
            s.collected.clear();
            s.connects.clear();
            (
                200,
                "OK",
                "application/json",
                b"{\"ok\":true}".to_vec(),
                vec![],
            )
        }
        _ => (
            404,
            "Not Found",
            "text/plain",
            b"hardvoy lab: no such path\n".to_vec(),
            vec![],
        ),
    };

    // a cookie the operator can trace: proves the browser kept state across
    // requests on this egress path
    let mut extra: Vec<(&str, String)> = extra.into_iter().collect();
    extra.push((
        "Set-Cookie",
        format!("hv_run={}; Path=/; SameSite=Lax", get("run")),
    ));
    let _ = stream.write_all(&httpf::response(status, reason, ctype, &payload, &extra));
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// TLS sniffer

fn serve_tls(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    match tlsf::ClientHello::from_record_stream(&mut stream) {
        Ok((hello, raw)) => {
            let mut summary = TlsSummary::compute(&hello, raw.len());
            summary.hello_len = hello.body_len;
            let cap = HelloCapture {
                label: "sniffer".into(),
                seen_at: stamp(),
                peer: peer.clone(),
                raw_hex: crate::util::hex(&raw),
                summary,
            };
            let mut s = state.lock().expect("lab state lock");
            s.hellos.push(cap);
            drop(s);
            let _ = stream.write_all(&tlsf::ALERT_HANDSHAKE_FAILURE);
            let _ = stream.flush();
        }
        Err(e) => {
            let mut s = state.lock().expect("lab state lock");
            s.hellos.push(HelloCapture {
                label: format!("sniffer-error: {e}"),
                seen_at: stamp(),
                peer,
                raw_hex: String::new(),
                summary: empty_summary(),
            });
            let _ = stream.write_all(&tlsf::ALERT_CLOSE_NOTIFY);
        }
    }
}

fn empty_summary() -> TlsSummary {
    TlsSummary {
        ja3: String::new(),
        ja3_string: String::new(),
        ja4: String::new(),
        ja4_raw: String::new(),
        wire_summary: String::new(),
        grease_present: false,
        record_version: 0,
        record_version_name: String::new(),
        legacy_version: 0,
        legacy_version_name: String::new(),
        highest_version: None,
        highest_version_name: None,
        supported_versions: Vec::new(),
        ciphers: Vec::new(),
        cipher_ids: Vec::new(),
        extensions: Vec::new(),
        extension_ids: Vec::new(),
        signature_algorithms: Vec::new(),
        supported_groups: Vec::new(),
        key_share_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        psk_key_exchange_modes: Vec::new(),
        alpn: Vec::new(),
        sni: None,
        compression_methods: Vec::new(),
        session_id_len: 0,
        hello_len: 0,
        total_bytes: 0,
        ciphers_clean: 0,
        extensions_clean: 0,
    }
}

// ---------------------------------------------------------------------------
// SSH sniffer

fn serve_ssh(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let banner = match sshf::read_banner(&mut stream) {
        Ok(b) => b,
        Err(_) => return,
    };
    let pkt = match sshf::read_packet(&mut stream) {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Ok(kex) = KexInit::from_payload(&pkt) {
        let hassh = kex.hassh();
        {
            let mut s = state.lock().expect("lab state lock");
            s.ssh.push(SshCapture {
                label: "client".into(),
                seen_at: stamp(),
                peer: peer.clone(),
                banner: banner.clone(),
                hassh: hassh.clone(),
                kex,
            });
        }
        // answer so the client does not just see a closed connection
        let ours = sshf::client_kexinit("minimal");
        let _ = stream.write_all(sshf::BANNER.as_bytes());
        let _ = stream.write_all(b"\r\n");
        let _ = stream.write_all(&ours.to_packet());
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlsf::HelloSpec;
    use std::io::Read;
    use std::time::{Duration, Instant};

    fn wait_connect(addr: SocketAddr) -> Option<TcpStream> {
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(addr) {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    #[test]
    fn lab_serves_page_collect_and_headers() {
        let lab = Lab::start().expect("lab starts");
        let mut s = wait_connect(lab.addrs.http).expect("connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: uv test\r\nAccept-Language: en-US,en;q=0.5\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let resp = String::from_utf8_lossy(&buf).into_owned();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("text/html"));
        assert!(resp.contains("hv_run="));

        // POST a probe payload
        let body = br#"{"canvas":"abc","webrtc":{"candidates":["candidate:0 1 UDP 1 192.168.1.5 1 typ host"]}}"#;
        let mut s2 = wait_connect(lab.addrs.http).expect("connect2");
        s2.write_all(format!("POST /collect?run=r7 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).unwrap();
        s2.write_all(body).unwrap();
        let mut b2 = Vec::new();
        s2.read_to_end(&mut b2).unwrap();
        assert!(String::from_utf8_lossy(&b2).contains("\"ok\":true"));

        let got = lab.collected_for("r7").expect("collected");
        assert_eq!(got.bytes, body.len());
        assert_eq!(got.payload["canvas"].as_str(), Some("abc"));

        let snap = lab.snapshot();
        assert_eq!(snap.requests.len(), 2);
        assert_eq!(
            snap.requests[0].profile.user_agent.as_deref(),
            Some("uv test")
        );
        assert_eq!(
            snap.requests[0].profile.accept_language.as_deref(),
            Some("en-US,en;q=0.5")
        );
        assert_eq!(snap.requests[1].request.method, "POST");
    }

    #[test]
    fn tls_sniffer_fingerprints_our_own_hello() {
        let lab = Lab::start().expect("lab starts");
        let hello = HelloSpec::stock().to_hello();
        let bytes = hello.to_bytes();
        let mut s = wait_connect(lab.addrs.tls).expect("connect tls");
        s.write_all(&bytes).unwrap();
        let mut resp = [0u8; 7];
        let _ = s.read(&mut resp);
        let got = {
            let snap = lab.snapshot();
            snap.hellos
        };
        assert_eq!(got.len(), 1, "no ClientHello captured");
        let sum = &got[0].summary;
        assert_eq!(sum.sni.as_deref(), Some("hardvoy.invalid"));
        assert_eq!(sum.ja3.len(), 32);
        assert!(sum.ja4.starts_with("t13i"));
        assert!(sum.ciphers.iter().any(|c| c == "TLS_AES_128_GCM_SHA256"));
        assert!(sum.alpn.contains(&"h2".to_string()));
        assert_eq!(got[0].raw_hex.len(), bytes.len() * 2);
    }

    #[test]
    fn tls_sniffer_reports_a_clear_error_for_cleartext() {
        let lab = Lab::start().expect("lab starts");
        let mut s = wait_connect(lab.addrs.tls).expect("connect tls");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut b = Vec::new();
        let _ = s.read_to_end(&mut b);
        let snap = lab.snapshot();
        assert_eq!(snap.hellos.len(), 1);
        assert!(snap.hellos[0].label.contains("not a TLS handshake record"));
    }

    #[test]
    fn ssh_sniffer_fingerprints_our_own_kexinit() {
        let lab = Lab::start().expect("lab starts");
        let mut s = wait_connect(lab.addrs.ssh).expect("connect ssh");
        let kex = sshf::client_kexinit("openssh9.9");
        s.write_all(b"SSH-2.0-TestClient_1.0\r\n").unwrap();
        s.write_all(&kex.to_packet()).unwrap();
        let mut b = Vec::new();
        let _ = s.read_to_end(&mut b);
        let snap = lab.snapshot();
        assert_eq!(snap.ssh.len(), 1);
        assert_eq!(snap.ssh[0].banner, "SSH-2.0-TestClient_1.0");
        assert_eq!(snap.ssh[0].hassh, kex.hassh());
        assert_eq!(snap.ssh[0].kex.kex_algorithms[0], "mlkem768x25519");
    }

    #[test]
    fn lab_records_peers_and_clear_works() {
        let lab = Lab::start().expect("lab starts");
        let mut s = wait_connect(lab.addrs.http).unwrap();
        s.write_all(b"GET /identity HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        let resp = String::from_utf8_lossy(&b).into_owned();
        assert!(resp.contains("\"lab\":\"hardvoy\""));
        assert!(resp.contains("127.0.0.1"));
        assert!(!lab.snapshot().connects.is_empty());
        let mut s2 = wait_connect(lab.addrs.http).unwrap();
        s2.write_all(b"POST /clear HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let mut b2 = Vec::new();
        s2.read_to_end(&mut b2).unwrap();
        let snap = lab.snapshot();
        assert!(snap.requests.is_empty());
        assert!(snap.connects.is_empty());
    }

    #[test]
    fn unknown_path_is_404_not_hang() {
        let lab = Lab::start().expect("lab starts");
        let t0 = Instant::now();
        let mut s = wait_connect(lab.addrs.http).unwrap();
        s.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        assert!(String::from_utf8_lossy(&b).starts_with("HTTP/1.1 404"));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
