//! Minimal W3C WebDriver client plus a geckodriver process manager.
//!
//! hardvoy drives a real Firefox, not a headless engine pretending to be one:
//! the fingerprint it measures is the one Firefox puts on the wire.
//!
//! Written by hand (plain HTTP/1.1 over a loopback socket) to keep the binary
//! dependency-light.

use crate::util::now_millis;
use serde_json::{Map, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct WdError {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for WdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "webdriver http {} — {}", self.status, self.message)
    }
}
impl std::error::Error for WdError {}

/// A geckodriver process listening on a free loopback port.
pub struct Geckodriver {
    pub addr: SocketAddr,
    child: Option<Child>,
    pub log_path: PathBuf,
}

impl Geckodriver {
    /// `binary` is the Firefox executable; `workdir` receives the driver log.
    pub fn start(binary: Option<&Path>, workdir: &Path) -> std::io::Result<Geckodriver> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener); // geckodriver binds the port itself
        let log_path = workdir.join("geckodriver.log");
        let log = std::fs::File::create(&log_path)?;
        let log_err = log.try_clone()?;
        let mut cmd = Command::new("geckodriver");
        cmd.arg("--port")
            .arg(addr.port().to_string())
            .arg("--host")
            .arg("127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        if let Some(b) = binary {
            cmd.env("MOZ_firefox_binary", b);
            cmd.arg("--binary").arg(b);
        }
        let child = cmd.spawn()?;
        let gd = Geckodriver {
            addr,
            child: Some(child),
            log_path,
        };
        // Wait for the port to answer. geckodriver keeps the connection open,
        // so read until the body shows up instead of waiting for EOF.
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            if wait_ready_once(addr).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "geckodriver did not become ready on {addr}; log at {}",
                        gd.log_path.display()
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(120));
        }
        let _ = &gd;
        Ok(gd)
    }
}

/// One `/status` poll: true once geckodriver says it is ready.
fn wait_ready_once(addr: SocketAddr) -> Result<(), String> {
    let mut s =
        TcpStream::connect_timeout(&addr, Duration::from_millis(800)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    // geckodriver 0.37 rejects a Host it did not bind, so present `localhost`
    let req = format!(
        "GET /status HTTP/1.1\r\nHost: localhost:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        addr.port()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        if buf.windows(6).any(|w| w == b"ready") {
            break;
        }
    }
    if String::from_utf8_lossy(&buf).contains("ready") {
        Ok(())
    } else {
        Err(format!("no ready in {} bytes", buf.len()))
    }
}

impl Drop for Geckodriver {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub struct Wd {
    addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub capabilities: Value,
}

impl Wd {
    pub fn new(addr: SocketAddr) -> Wd {
        Wd { addr }
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, WdError> {
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b).unwrap_or_default(),
            None => Vec::new(),
        };
        let mut stream = TcpStream::connect(self.addr).map_err(|e| WdError {
            status: 0,
            message: format!("connect to geckodriver at {}: {e}", self.addr),
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
        let head = format!(
            // geckodriver 0.37 only accepts the Host it bound, which is
            // `localhost:PORT`; a numeric Host is rejected outright.
            "{method} {path} HTTP/1.1\r\nHost: localhost:{}\r\nAccept: application/json\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr.port(),
            body_bytes.len()
        );
        stream.write_all(head.as_bytes()).map_err(|e| WdError {
            status: 0,
            message: e.to_string(),
        })?;
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).map_err(|e| WdError {
                status: 0,
                message: e.to_string(),
            })?;
        }
        stream.flush().ok();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|e| WdError {
            status: 0,
            message: e.to_string(),
        })?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let sep = match text.find("\r\n\r\n") {
            Some(i) => i,
            None => {
                return Err(WdError {
                    status: 0,
                    message: format!("no HTTP response from geckodriver ({text:?})"),
                })
            }
        };
        let headers = text[..sep].to_ascii_lowercase();
        let status: u16 = headers
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let payload = text[sep + 4..].trim_end().to_string();
        let parsed: Value = serde_json::from_str(&payload).unwrap_or_else(|e| {
            Value::Object(
                [
                    ("value".into(), Value::String(payload.clone())),
                    ("hardvoy_parse_error".into(), Value::String(e.to_string())),
                ]
                .into_iter()
                .collect::<Map<String, Value>>(),
            )
        });
        if status >= 400 {
            let msg = parsed
                .get("value")
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    o => o
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown webdriver error")
                        .to_string(),
                })
                .unwrap_or_else(|| "no message".to_string());
            return Err(WdError {
                status,
                message: msg,
            });
        }
        Ok(parsed)
    }

    pub fn status(&self) -> Result<Value, WdError> {
        self.request("GET", "/status", None)
    }

    /// Create a session. `prefs` are Firefox preferences set before the first
    /// navigation, `profile_dir` pins a profile directory so it can be reused
    /// or inspected after the run.
    pub fn new_session(
        &self,
        binary: Option<&Path>,
        profile_dir: Option<&Path>,
        extra_args: &[String],
        prefs: &Map<String, Value>,
        accept_insecure_certs: bool,
    ) -> Result<SessionInfo, WdError> {
        let mut args: Vec<String> = vec!["-headless".into(), "-no-remote".into()];
        if let Some(p) = profile_dir {
            args.push("-profile".into());
            args.push(p.display().to_string());
        }
        args.extend(extra_args.iter().cloned());
        let mut opts = Map::new();
        opts.insert(
            "args".into(),
            Value::Array(args.into_iter().map(Value::String).collect()),
        );
        if let Some(b) = binary {
            opts.insert("binary".into(), Value::String(b.display().to_string()));
        }
        if !prefs.is_empty() {
            opts.insert("prefs".into(), Value::Object(prefs.clone()));
        }
        // geckodriver 0.37 wants `log` as an object; leaving it unset keeps the
        // driver's own default and avoids a 400 on session creation
        let mut always = Map::new();
        always.insert("browserName".into(), Value::String("firefox".into()));
        always.insert(
            "acceptInsecureCerts".into(),
            Value::Bool(accept_insecure_certs),
        );
        always.insert("pageLoadStrategy".into(), Value::String("normal".into()));
        always.insert("moz:firefoxOptions".into(), Value::Object(opts));
        let body = serde_json::json!({
            "capabilities": { "alwaysMatch": always, "firstMatch": [{}] },
            "desiredCapabilities": { "browserName": "firefox" }
        });
        let v = self.request("POST", "/session", Some(&body))?;
        let value = v.get("value").cloned().unwrap_or(Value::Null);
        let caps = value
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| value.clone());
        let id = value
            .get("sessionId")
            .and_then(|s| s.as_str())
            .or_else(|| caps.get("sessionId").and_then(|s| s.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_default();
        if id.is_empty() {
            return Err(WdError {
                status: 500,
                message: format!("geckodriver returned no session id: {value}"),
            });
        }
        Ok(SessionInfo {
            id,
            capabilities: caps,
        })
    }

    pub fn navigate(&self, sid: &str, url: &str) -> Result<(), WdError> {
        self.request(
            "POST",
            &format!("/session/{sid}/url"),
            Some(&serde_json::json!({ "url": url })),
        )?;
        Ok(())
    }

    pub fn execute(&self, sid: &str, script: &str, args: &[Value]) -> Result<Value, WdError> {
        let v = self.request(
            "POST",
            &format!("/session/{sid}/execute/sync"),
            Some(&serde_json::json!({ "script": script, "args": args })),
        )?;
        Ok(v.get("value").cloned().unwrap_or(Value::Null))
    }

    pub fn set_timeouts(
        &self,
        sid: &str,
        page_load_ms: u64,
        script_ms: u64,
    ) -> Result<(), WdError> {
        self.request(
            "POST",
            &format!("/session/{sid}/timeouts"),
            Some(&serde_json::json!({
                "script": script_ms,
                "pageLoad": page_load_ms,
                "implicit": 0
            })),
        )?;
        Ok(())
    }

    /// PNG screenshot of the current page (base64-decoded).
    pub fn screenshot(&self, sid: &str) -> Result<Vec<u8>, WdError> {
        let v = self.request("GET", &format!("/session/{sid}/screenshot"), None)?;
        let b64 = v
            .get("value")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string();
        if b64.is_empty() {
            return Err(WdError {
                status: 500,
                message: format!("no screenshot in response: {v}"),
            });
        }
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| WdError {
                status: 500,
                message: format!("screenshot base64: {e}"),
            })
    }

    pub fn source(&self, sid: &str) -> Result<String, WdError> {
        let v = self.request("GET", &format!("/session/{sid}/source"), None)?;
        Ok(v.get("value")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string())
    }

    pub fn delete_session(&self, sid: &str) {
        let _ = self.request("DELETE", &format!("/session/{sid}"), None);
    }
}

/// Preferences that model an operator posture. These are the knobs a real
/// operator turns, and each one measurably changes the fingerprint, which is
/// exactly what hardvoy is meant to demonstrate.
pub fn ff_profile(name: &str) -> Map<String, Value> {
    let mut p = Map::new();
    // sane lab defaults for every profile
    p.insert(
        "datareporting.policy.dataSubmissionEnabled".into(),
        Value::Bool(false),
    );
    p.insert(
        "datareporting.healthreport.uploadEnabled".into(),
        Value::Bool(false),
    );
    p.insert(
        "app.shield.optoutstudies.enabled".into(),
        Value::Bool(false),
    );
    p.insert("browser.ml.chat.enabled".into(), Value::Bool(false));
    p.insert("extensions.pocket.enabled".into(), Value::Bool(false));
    p.insert(
        "browser.startup.homepage_override.mstone".into(),
        Value::String("ignore".into()),
    );
    p.insert(
        "privacy.trackingprotection.enabled".into(),
        Value::Bool(false),
    );
    p.insert(
        "privacy.trackingprotection.socialtracking.enabled".into(),
        Value::Bool(false),
    );
    p.insert(
        "network.http.referer.XOriginPolicy".into(),
        Value::Number(0.into()),
    );
    p.insert(
        "network.proxy.allow_hijacking_localhost".into(),
        Value::Bool(true),
    );
    p.insert("dom.webnotifications.enabled".into(), Value::Bool(false));
    p.insert(
        "media.autoplay.blocking_policy".into(),
        Value::Number(0.into()),
    );
    p.insert("media.peerconnection.enabled".into(), Value::Bool(true));
    p.insert(
        "media.peerconnection.ice.no_host".into(),
        Value::Bool(false),
    );
    p.insert(
        "media.peerconnection.ice.proxy_only".into(),
        Value::Bool(false),
    );
    p.insert(
        "media.getusermedia.screensharing.enabled".into(),
        Value::Bool(true),
    );
    p.insert(
        "privacy.webrtc.hideGlobalIndicator".into(),
        Value::Bool(true),
    );
    p.insert("general.smoothScroll".into(), Value::Bool(false));
    p.insert("layers.acceleration.disabled".into(), Value::Bool(false));
    p.insert(
        "gfx.font_rendering.cleartype_params.rendering_mode".into(),
        Value::Number(2.into()),
    );
    p.insert(
        "intl.accept_languages".into(),
        Value::String("en-US,en;q=0.5".into()),
    );

    match name {
        // Stock Firefox: mDNS-obfuscated host candidates, no RFP.
        "stock" => {}
        // The leaky posture: mDNS masking off, so host candidates carry the
        // real interface address. This is what the lab page plants a hit for.
        "leaky" => {
            p.insert(
                "media.peerconnection.ice.obfuscate_host_addresses".into(),
                Value::Bool(false),
            );
            p.insert(
                "media.peerconnection.ice.obfuscate_host_addresses.available".into(),
                Value::Bool(true),
            );
        }
        // No WebRTC at all.
        "norbrtc" => {
            p.insert("media.peerconnection.enabled".into(), Value::Bool(false));
        }
        // Resist Fingerprinting: Firefox fakes the clock, timezone, screen and
        // round-trips timers; expect a very different fingerprint.
        "rfp" => {
            p.insert("privacy.resistFingerprinting".into(), Value::Bool(true));
            p.insert(
                "privacy.resistFingerprinting.letterboxing".into(),
                Value::Bool(false),
            );
        }
        // Chrome-ish headers/hints out of Firefox: shows that header shape and
        // client hints are a correlation vector even on Firefox.
        "chromelike" => {
            p.insert("general.useragent.override".into(), Value::String("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into()));
            p.insert(
                "network.http.user-agent-servertime-offset".into(),
                Value::Number(0.into()),
            );
            p.insert("dom.security.https_first".into(), Value::Bool(false));
            p.insert(
                "network.http.referer.defaultPolicy".into(),
                Value::Number(0.into()),
            );
        }
        other => {
            // Unknown profile names stay honest: stock plus a note.
            p.insert(
                "hardvoy.unknown_profile".into(),
                Value::String(other.to_string()),
            );
        }
    }
    p
}

/// Add the proxy settings that route the browser through hardvoy's forwarder,
/// which is what makes "direct" and "tor" comparable runs.
pub fn with_proxy(prefs: &mut Map<String, Value>, proxy: SocketAddr, direct_to_proxy: bool) {
    if !direct_to_proxy {
        return;
    }
    prefs.insert("network.proxy.type".into(), Value::Number(1.into()));
    prefs.insert(
        "network.proxy.http".into(),
        Value::String(proxy.ip().to_string()),
    );
    prefs.insert(
        "network.proxy.http_port".into(),
        Value::Number(proxy.port().into()),
    );
    prefs.insert(
        "network.proxy.ssl".into(),
        Value::String(proxy.ip().to_string()),
    );
    prefs.insert(
        "network.proxy.ssl_port".into(),
        Value::Number(proxy.port().into()),
    );
    prefs.insert(
        "network.proxy.ftp".into(),
        Value::String(proxy.ip().to_string()),
    );
    prefs.insert(
        "network.proxy.ftp_port".into(),
        Value::Number(proxy.port().into()),
    );
    prefs.insert(
        "network.proxy.no_proxies_on".into(),
        Value::String("".into()),
    );
    prefs.insert(
        "network.proxy.share_proxy_settings".into(),
        Value::Bool(true),
    );
    // bypass Firefox's own .onion handling: the forwarder/upstream resolves it
    prefs.insert("network.dns.blockDotOnion".into(), Value::Bool(true));
    prefs.insert(
        "network.proxy.http".into(),
        Value::String(proxy.ip().to_string()),
    );
    prefs.insert(
        "network.proxy.allow_hijacking_localhost".into(),
        Value::Bool(true),
    );
    let _ = now_millis();
}

/// Point Firefox at a SOCKS5 proxy (Tor's), with remote DNS.
///
/// This is how a real Tor Browser reaches an onion service: the name must be
/// resolved *after* the exit, so Firefox must not resolve `.onion` itself, and
/// an HTTP proxy is not enough — SOCKS carries the name to Tor.
pub fn with_socks(prefs: &mut Map<String, Value>, proxy: SocketAddr) {
    // manual proxy configuration: without this Firefox ignores the fields below
    prefs.insert("network.proxy.type".into(), Value::Number(1.into()));
    prefs.insert(
        "network.proxy.socks".into(),
        Value::String(proxy.ip().to_string()),
    );
    prefs.insert(
        "network.proxy.socks_port".into(),
        Value::Number(proxy.port().into()),
    );
    prefs.insert(
        "network.proxy.socks_version".into(),
        Value::Number(5.into()),
    );
    prefs.insert("network.proxy.socks_remote_dns".into(), Value::Bool(true));
    prefs.insert(
        "network.proxy.no_proxies_on".into(),
        Value::String(String::new()),
    );
    // .onion must not be blocked locally when the resolver is Tor
    prefs.insert("network.dns.blockDotOnion".into(), Value::Bool(false));
    // a page that tries a non-Tor resource would leak around the proxy
    prefs.insert("network.proxy.fail_closed".into(), Value::Bool(true));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_differ_where_it_matters() {
        let stock = ff_profile("stock");
        let leaky = ff_profile("leaky");
        let rfp = ff_profile("rfp");
        let nortc = ff_profile("norbrtc");
        assert_eq!(
            stock.get("media.peerconnection.ice.obfuscate_host_addresses"),
            None,
            "stock must not set the mDNS pref"
        );
        assert_eq!(
            leaky.get("media.peerconnection.ice.obfuscate_host_addresses"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            rfp.get("privacy.resistFingerprinting"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            nortc.get("media.peerconnection.enabled"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn unknown_profile_is_recorded_not_silently_dropped() {
        let p = ff_profile("banana");
        assert_eq!(
            p.get("hardvoy.unknown_profile"),
            Some(&Value::String("banana".into()))
        );
    }

    #[test]
    fn proxy_prefs_point_at_the_forwarder() {
        let mut p = ff_profile("stock");
        let addr: SocketAddr = "127.0.0.1:8099".parse().unwrap();
        with_proxy(&mut p, addr, true);
        assert_eq!(
            p.get("network.proxy.http"),
            Some(&Value::String("127.0.0.1".into()))
        );
        assert_eq!(
            p.get("network.proxy.http_port"),
            Some(&Value::Number(8099.into()))
        );
        assert_eq!(
            p.get("network.proxy.ssl_port"),
            Some(&Value::Number(8099.into()))
        );
        assert_eq!(
            p.get("network.proxy.no_proxies_on"),
            Some(&Value::String("".into()))
        );
        let mut q = ff_profile("stock");
        with_proxy(&mut q, addr, false);
        assert_eq!(q.get("network.proxy.http"), None);
    }

    #[test]
    fn wd_errors_carry_the_status() {
        let e = WdError {
            status: 404,
            message: "no such session".into(),
        };
        assert!(format!("{e}").contains("404"));
    }

    #[test]
    fn status_poll_works_against_a_keep_alive_server() {
        // a driver that answers /status and keeps the socket open: reading to
        // EOF would hang, so the poll must stop at the body
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 256];
            let _ = c.read(&mut buf);
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\n\r\n{\"value\":{\"ready\":true}}xx")
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });
        wait_ready_once(addr).expect("ready detected without waiting for EOF");
    }

    #[test]
    fn requests_present_a_host_geckodriver_accepts() {
        // regression: geckodriver 0.37 answers "Rejected request with Host
        // header 127.0.0.1" and then never replies, which looked like a hang
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = c.read(&mut buf).unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(head);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        });
        let wd = Wd::new(addr);
        let _ = wd.status();
        let head = rx.recv().unwrap();
        assert!(
            head.contains(&format!("Host: localhost:{}", addr.port())),
            "host header: {head}"
        );
    }

    #[test]
    fn status_poll_fails_when_nothing_listens() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        assert!(wait_ready_once(addr).is_err());
    }

    #[test]
    fn status_poll_says_no_when_the_answer_is_wrong() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 256];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\nnope");
        });
        let e = wait_ready_once(addr).unwrap_err();
        assert!(e.contains("no ready"), "{e}");
    }

    #[test]
    fn socks_profile_points_firefox_at_tor_with_remote_dns() {
        let mut p = ff_profile("stock");
        with_socks(&mut p, "127.0.0.1:9050".parse().unwrap());
        assert_eq!(p["network.proxy.socks"], serde_json::json!("127.0.0.1"));
        assert_eq!(p["network.proxy.socks_port"], serde_json::json!(9050));
        assert_eq!(p["network.proxy.socks_version"], serde_json::json!(5));
        assert_eq!(p["network.proxy.socks_remote_dns"], serde_json::json!(true));
        assert_eq!(p["network.dns.blockDotOnion"], serde_json::json!(false));
    }

    #[test]
    fn http_profile_does_not_block_dot_onion_resolution_locally_in_tor_mode() {
        // the direct path uses an HTTP forwarder; .onion is blocked there so a
        // stray onion URL fails loudly instead of dialing out
        let mut p = ff_profile("stock");
        with_proxy(&mut p, "127.0.0.1:8080".parse().unwrap(), true);
        assert_eq!(p["network.proxy.http"], serde_json::json!("127.0.0.1"));
        assert_eq!(p["network.proxy.http_port"], serde_json::json!(8080));
        assert_eq!(p["network.dns.blockDotOnion"], serde_json::json!(true));
    }

    #[test]
    fn request_to_a_dead_driver_fails_cleanly() {
        // nothing is listening on this port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let wd = Wd::new(addr);
        let e = wd.status().unwrap_err();
        assert_eq!(e.status, 0);
        assert!(e.message.contains("connect to geckodriver"));
    }
}
