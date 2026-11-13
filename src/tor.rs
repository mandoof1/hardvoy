//! Tor: a control-port client (subset of RFC 9051) and a Tor client we own.
//!
//! The system Tor on this machine exposes a SOCKS port but no control port, so
//! NEWNYM and circuit evidence need a Tor instance with both. `TorInstance`
//! starts one with a hidden service in front of the local lab, which gives the
//! scan a second, genuinely different egress path to compare.

use crate::httpf::{build_request, parse_response};
use crate::util;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// "127.0.0.1:port" as a SocketAddr.
fn loopback(port: u16) -> Result<SocketAddr, String> {
    format!("127.0.0.1:{port}")
        .parse::<SocketAddr>()
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct TorError {
    pub stage: String,
    pub detail: String,
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tor {}: {}", self.stage, self.detail)
    }
}

/// One circuit as the control port reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Circuit {
    pub id: u32,
    pub purpose: String,
    pub build_type: String,
    pub build_flags: String,
    pub state: String,
    pub reason: String,
    pub time_created: String,
    pub path: Vec<String>,
    pub exit: Option<String>,
}

impl Circuit {
    /// Relay fingerprints along the path — enough to prove two circuits are
    /// genuinely different paths.
    pub fn path_fingerprints(&self) -> Vec<String> {
        self.path
            .iter()
            .filter_map(|h| hop_fingerprint(h))
            .collect()
    }

    /// Fingerprint of the last hop: the relay that talks to the destination.
    pub fn exit_fingerprint(&self) -> Option<String> {
        self.exit.as_deref().and_then(hop_fingerprint)
    }
}

/// Pull the 40-hex fingerprint out of a hop, which Tor writes as
/// `$FINGERPRINT=nickname`, `$FINGERPRINT~nickname`, or
/// `address=$FINGERPRINT=nickname`.
pub fn hop_fingerprint(hop: &str) -> Option<String> {
    let h = hop.trim_start_matches('$');
    for part in h.split(['=', '~']) {
        let p = part.trim_start_matches('$');
        if p.len() == 40 && p.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(p.to_ascii_uppercase());
        }
    }
    None
}

fn is_state(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "NEW"
            | "EXTENDED"
            | "GUARDWAIT"
            | "LAUNDRY"
            | "BUILT"
            | "RETRYING"
            | "CLOSED"
            | "TRYING"
            | "OPENING"
            | "FAILED"
    )
}

/// Parse a `circuit-status` line.
///
/// Tor 0.4.9 writes `<id> <state> <routers> KEY=VALUE ...`; older releases
/// wrote `<id> <purpose> <build-type> <build-info> <state> [reason] [times]
/// <routers>`. Both are handled: the state is recognised by name, the routers
/// by their leading `$`, and any leftover bare tokens are read positionally.
pub fn parse_circuit_line(line: &str) -> Option<Circuit> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 2 {
        return None;
    }
    let id: u32 = toks[0].parse().ok()?;
    let mut c = Circuit {
        id,
        ..Default::default()
    };
    let mut bare: Vec<String> = Vec::new();
    for t in &toks[1..] {
        if t.starts_with('$') {
            for hop in t.split(',') {
                c.path.push(hop.to_string());
            }
        } else if let Some((k, v)) = t.split_once('=') {
            match k.to_ascii_uppercase().as_str() {
                "PURPOSE" => c.purpose = v.to_lowercase(),
                "BUILD_TYPE" => c.build_type = v.to_lowercase(),
                "BUILD_FLAGS" => c.build_flags = v.to_string(),
                "REASON" => c.reason = v.to_string(),
                "TIME_CREATED" => c.time_created = v.to_string(),
                _ => {}
            }
        } else if is_state(t) && c.state.is_empty() {
            c.state = t.to_ascii_uppercase();
        } else if t.chars().all(|c| c.is_ascii_digit()) && t.len() >= 10 {
            // legacy unix timestamp: not needed for the report
        } else {
            bare.push(t.to_string());
        }
    }
    if c.state.is_empty() {
        return None;
    }
    if c.purpose.is_empty() {
        // legacy positional form: purpose, build type, build info, reason
        c.purpose = bare.first().cloned().unwrap_or_default().to_lowercase();
    }
    if c.build_type.is_empty() && bare.len() > 1 {
        c.build_type = bare[1].to_lowercase();
    }
    if c.reason.is_empty() && !c.purpose.is_empty() && bare.len() > 3 {
        c.reason = bare[3].clone();
    }
    c.exit = c.path.last().cloned();
    Some(c)
}

/// Control-port reply framing.
///
/// Tor prefixes reply lines with a 3-digit status: `NNN-` is a middle line,
/// `NNN ` ends the reply, and `NNN+` means the body follows verbatim until a
/// line containing only `.` — which is how `GETINFO circuit-status` returns its
/// table. 650 lines are asynchronous events and are skipped.
#[derive(Debug, Default)]
struct ReplyScanner {
    in_plus_body: bool,
    out: Vec<String>,
    final_code: Option<u16>,
}

impl ReplyScanner {
    /// Feed one wire line; returns true once the reply is complete.
    fn push(&mut self, line: &str) -> bool {
        if self.in_plus_body {
            if line == "." {
                self.in_plus_body = false;
            } else {
                self.out.push(line.to_string());
            }
            return false;
        }
        if line.len() < 4 {
            return false;
        }
        let code: u16 = line[..3].parse().unwrap_or(0);
        let sep = line.as_bytes()[3];
        if code == 650 {
            return false;
        }
        self.final_code = Some(code);
        self.out.push(line[4..].to_string());
        match sep {
            b'+' => {
                self.in_plus_body = true;
                false
            }
            b' ' => true,
            _ => false,
        }
    }

    fn finish(self) -> Result<(u16, Vec<String>), TorError> {
        match self.final_code {
            Some(code) if code >= 400 => Err(TorError {
                stage: "command".into(),
                detail: format!("{code}: {}", self.out.join(" | ")),
            }),
            Some(code) => Ok((code, self.out)),
            None => Err(TorError {
                stage: "read".into(),
                detail: "control port closed without a reply".into(),
            }),
        }
    }
}

/// Minimal Tor control-port client (a subset of RFC 9051 is all we need).
///
/// Modern Tor sends no unsolicited greeting, so `connect` introduces itself
/// with `PROTOCOLINFO 1` and keeps the answer: that is where the cookie file
/// location is published.
#[derive(Debug)]
pub struct Control {
    stream: TcpStream,
    reader: std::io::BufReader<TcpStream>,
    pub log: Vec<String>,
    protocol_info: Vec<String>,
}

impl Control {
    pub fn connect(addr: SocketAddr, timeout: Duration) -> Result<Control, TorError> {
        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| TorError {
            stage: "connect".into(),
            detail: format!("{addr}: {e}"),
        })?;
        stream.set_read_timeout(Some(timeout)).ok();
        let reader = std::io::BufReader::new(stream.try_clone().map_err(|e| TorError {
            stage: "clone".into(),
            detail: e.to_string(),
        })?);
        let mut c = Control {
            stream,
            reader,
            log: Vec::new(),
            protocol_info: Vec::new(),
        };
        c.protocol_info = c.cmd("PROTOCOLINFO 1")?;
        Ok(c)
    }

    /// Read one reply (see [`ReplyScanner`] for the framing).
    fn read_reply(&mut self) -> Result<(u16, Vec<String>), TorError> {
        let mut sc = ReplyScanner::default();
        loop {
            let mut s = String::new();
            match self.reader.read_line(&mut s) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(TorError {
                        stage: "read".into(),
                        detail: e.to_string(),
                    })
                }
            }
            if sc.push(s.trim_end_matches(['\r', '\n'])) {
                break;
            }
        }
        sc.finish()
    }

    pub fn cmd(&mut self, line: &str) -> Result<Vec<String>, TorError> {
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .map_err(|e| TorError {
                stage: "write".into(),
                detail: format!("{line}: {e}"),
            })?;
        self.stream.flush().ok();
        let (_, lines) = self.read_reply()?;
        self.log.push(format!("{line} -> {} lines", lines.len()));
        Ok(lines)
    }

    pub fn getinfo(&mut self, key: &str) -> Result<Vec<String>, TorError> {
        self.cmd(&format!("GETINFO {key}"))
    }

    pub fn signal(&mut self, sig: &str) -> Result<(), TorError> {
        self.cmd(&format!("SIGNAL {sig}"))?;
        Ok(())
    }

    pub fn version(&mut self) -> Result<String, TorError> {
        let lines = self.getinfo("version")?;
        let first = lines.into_iter().next().unwrap_or_default();
        Ok(first.strip_prefix("version=").unwrap_or(&first).to_string())
    }

    pub fn circuits(&mut self) -> Result<Vec<Circuit>, TorError> {
        let lines = self.getinfo("circuit-status")?;
        Ok(lines.iter().filter_map(|l| parse_circuit_line(l)).collect())
    }

    /// Cookie authentication: take the cookie path from PROTOCOLINFO when
    /// Tor publishes one, otherwise use the data directory we passed to Tor.
    ///
    /// Tor 0.4.9 wants the bare hex — quoting it gives "Wrong length on
    /// authentication cookie" — and hex never needs quoting.
    pub fn authenticate(&mut self, data_dir: &Path) -> Result<(), TorError> {
        if self.protocol_info.is_empty() {
            let l = self.cmd("PROTOCOLINFO 1")?;
            self.protocol_info = l.clone();
        }
        let mut cookie_path: Option<PathBuf> = None;
        for l in &self.protocol_info {
            if let Some(i) = l.find("COOKIEFILE=") {
                let rest = &l[i + 11..];
                let p = rest.trim_matches('"').split('"').next().unwrap_or("");
                if !p.is_empty() {
                    let pb = PathBuf::from(p);
                    // Tor publishes an absolute path; a relative one is
                    // relative to the data directory we started it with.
                    cookie_path = Some(if pb.is_absolute() {
                        pb
                    } else {
                        data_dir.join(pb)
                    });
                }
            }
        }
        let path = cookie_path.unwrap_or_else(|| data_dir.join("control_auth"));
        let bytes = std::fs::read(&path).map_err(|e| TorError {
            stage: "cookie-file".into(),
            detail: format!("{}: {e}", path.display()),
        })?;
        if bytes.len() != 32 {
            return Err(TorError {
                stage: "cookie-file".into(),
                detail: format!("{}: expected 32 bytes, got {}", path.display(), bytes.len()),
            });
        }
        let hex = util::hex(&bytes);
        self.cmd(&format!("AUTHENTICATE {hex}"))?;
        Ok(())
    }
}

/// A Tor client owned by this scan, with a hidden service in front of the lab.
pub struct TorInstance {
    child: Option<Child>,
    pub socks: SocketAddr,
    pub control: SocketAddr,
    pub onion: String,
    pub data_dir: PathBuf,
    pub hs_dir: PathBuf,
    pub log_path: PathBuf,
    pub version: String,
    pub started_at: String,
    pub boot_seconds: f64,
    /// How long one onion fetch may take. Publishing a brand-new hidden
    /// service on a busy network can take minutes, so this is generous.
    pub fetch_timeout: Duration,
    /// Attempts made while waiting for the onion service to become reachable.
    pub fetch_attempts: usize,
    /// Last failure seen while waiting, for the report.
    pub last_fetch_error: String,
}

impl TorInstance {
    /// Start our own Tor. `forwards` maps hidden-service port -> local port.
    pub fn start(
        workdir: &std::path::Path,
        forwards: &[(u16, u16)],
        timeout: Duration,
    ) -> Result<TorInstance, TorError> {
        let err = |stage: &str, detail: String| TorError {
            stage: stage.into(),
            detail,
        };
        let socks_port = util::free_port().map_err(|e| err("free-port", e))?;
        let control_port = util::free_port().map_err(|e| err("free-port", e))?;
        let socks = loopback(socks_port).map_err(|e| err("socks-address", e))?;
        let control = loopback(control_port).map_err(|e| err("control-address", e))?;
        let data_dir = workdir.join("tor-data");
        let hs_dir = workdir.join("tor-hs");
        std::fs::create_dir_all(workdir).map_err(|e| err("workdir", e.to_string()))?;
        for d in [&data_dir, &hs_dir] {
            std::fs::create_dir_all(d).map_err(|e| err("data-dir", e.to_string()))?;
            // Tor refuses a hidden-service directory other users can read
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| err("data-dir-mode", e.to_string()))?;
            }
        }
        // `-f /dev/null` is rejected by modern Tor, and the system torrc would
        // add ports and options we do not control, so point at an empty file.
        let empty_torrc = workdir.join("hardvoy-torrc");
        std::fs::write(
            &empty_torrc,
            b"# hardvoy: every option is passed on the command line\n",
        )
        .map_err(|e| err("torrc", e.to_string()))?;
        // A hidden-service directory left by an earlier run already holds a
        // hostname; drop it so "wait for the address" means *this* run.
        let _ = std::fs::remove_file(hs_dir.join("hostname"));
        let log_path = workdir.join("tor.log");
        let log = std::fs::File::create(&log_path).map_err(|e| err("log", e.to_string()))?;
        let log2 = log.try_clone().ok();

        // Tor wants option and value as separate arguments.
        let mut pairs: Vec<(&str, String)> = vec![
            ("--defaults-torrc", "DEVNULL".into()),
            ("-f", empty_torrc.display().to_string()),
            ("--DataDirectory", data_dir.display().to_string()),
            ("--SocksPort", format!("127.0.0.1:{socks_port}")),
            ("--ControlPort", format!("127.0.0.1:{control_port}")),
            ("--CookieAuthentication", "1".into()),
            (
                "--CookieAuthFile",
                data_dir.join("control_auth").display().to_string(),
            ),
            ("--HiddenServiceDir", hs_dir.display().to_string()),
            ("--HiddenServiceVersion", "3".into()),
            (
                "--Log",
                format!(
                    "{} file {}",
                    // HARDVOY_TOR_LOG=info (or debug) when a scan needs to see
                    // what tor is doing with the hidden service
                    std::env::var("HARDVOY_TOR_LOG").unwrap_or_else(|_| "notice".to_string()),
                    log_path.display()
                ),
            ),
            ("--SafeLogging", "0".into()),
            ("--ORPort", "0".into()),
            ("__OwningControllerProcess", std::process::id().to_string()),
        ];
        for (hs_port, local_port) in forwards {
            pairs.push((
                "--HiddenServicePort",
                format!("{hs_port} 127.0.0.1:{local_port}"),
            ));
        }
        let mut args: Vec<String> = Vec::new();
        for (k, v) in pairs {
            args.push(k.to_string());
            args.push(v);
        }

        let started_at = util::rfc3339_utc(util::now_millis());
        let t0 = Instant::now();
        let child = Command::new("tor")
            .args(&args)
            .stdout(Stdio::from(
                log.try_clone().map_err(|e| err("log", e.to_string()))?,
            ))
            .stderr(log2.map(Stdio::from).unwrap_or(Stdio::null()))
            .spawn()
            .map_err(|e| err("spawn", e.to_string()))?;

        // The onion address appears once Tor has written it into its HS dir.
        let mut onion = String::new();
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Ok(h) = std::fs::read_to_string(hs_dir.join("hostname")) {
                let h = h.trim().to_string();
                if !h.is_empty() {
                    onion = h;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if onion.is_empty() {
            let mut inst = TorInstance {
                child: Some(child),
                socks,
                control,
                onion: String::new(),
                data_dir: data_dir.clone(),
                hs_dir: hs_dir.clone(),
                log_path: log_path.clone(),
                version: String::new(),
                started_at,
                boot_seconds: t0.elapsed().as_secs_f64(),
                fetch_timeout: Duration::from_secs(150),
                fetch_attempts: 0,
                last_fetch_error: String::new(),
            };
            inst.stop();
            return Err(err(
                "hostname",
                format!(
                    "tor wrote no hidden service address in {}s; see {}",
                    timeout.as_secs(),
                    log_path.display()
                ),
            ));
        }

        // Prove the control port really works before the caller relies on it.
        // Tor opens it a moment after writing the onion address, so poll.
        let mut inst = TorInstance {
            child: Some(child),
            socks,
            control,
            onion,
            data_dir,
            hs_dir,
            log_path: log_path.clone(),
            version: String::new(),
            started_at,
            boot_seconds: t0.elapsed().as_secs_f64(),
            fetch_timeout: Duration::from_secs(150),
            fetch_attempts: 0,
            last_fetch_error: String::new(),
        };
        let mut c = None;
        let deadline = Instant::now() + timeout;
        let mut last = String::from("not tried");
        while Instant::now() < deadline {
            match Control::connect(control, Duration::from_secs(10)) {
                Ok(mut conn) => match conn.authenticate(&inst.data_dir) {
                    Ok(()) => {
                        c = Some(conn);
                        break;
                    }
                    Err(e) => last = e.detail,
                },
                Err(e) => last = e.detail,
            }
            let dead = inst
                .child
                .as_mut()
                .map(|ch| ch.try_wait().ok().flatten().is_some())
                .unwrap_or(true);
            if dead {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let Some(mut c) = c else {
            inst.stop();
            return Err(err(
                "control",
                format!(
                    "control port at {control} did not authenticate in {}s: {last}; see {}",
                    timeout.as_secs(),
                    log_path.display()
                ),
            ));
        };
        inst.version = c.version().unwrap_or_default();
        Ok(inst)
    }

    /// Wait until the hidden service answers, i.e. until the Tor -> lab path
    /// is genuinely usable. Returns the seconds it took.
    pub fn wait_ready(&mut self, timeout: Duration) -> Result<f64, String> {
        let t0 = Instant::now();
        let deadline = t0 + timeout;
        let mut last = String::from("not tried");
        let mut attempts = 0usize;
        while Instant::now() < deadline {
            attempts += 1;
            self.fetch_attempts = attempts;
            self.last_fetch_error = last.clone();
            match self.fetch("GET", "/identity", None) {
                Ok((200, _)) => return Ok(t0.elapsed().as_secs_f64()),
                Ok((status, _)) => last = format!("status {status}"),
                Err(e) => last = e,
            }
            // A v3 onion service has to publish its descriptor to six HSDirs
            // before any client can fetch it, and the first attempt usually
            // lands before that. Rotate the path and keep asking, but say so:
            // a silent minute of waiting looks like a hang from the outside.
            if attempts % 6 == 0 {
                eprintln!(
                    "hardvoy: tor: onion service not reachable yet (attempt {attempts}, {last})"
                );
                let _ = self.newnym();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(format!(
            "hidden service not reachable in {}s: {last}",
            timeout.as_secs()
        ))
    }

    /// One HTTP request to our own hidden service, over Tor's SOCKS port.
    ///
    /// This is the proof that the onion path works end to end: the request
    /// leaves through Tor, the name is resolved remotely, and the lab records
    /// the request that came out the other side.
    pub fn fetch(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, String), String> {
        let mut headers: Vec<(&str, &str)> = vec![
            ("Host", self.onion.as_str()),
            ("User-Agent", "hardvoy/tor-probe"),
            ("Accept", "text/html,application/xhtml+xml,*/*;q=0.8"),
            ("Connection", "close"),
        ];
        let body_bytes = body.map(|b| b.to_vec()).unwrap_or_default();
        if !body_bytes.is_empty() {
            headers.push(("Content-Type", "text/plain"));
        }
        let wire = build_request(method, path, &headers, &body_bytes);
        let mut sock = crate::socks::connect(self.socks, &self.onion, 80, None, self.fetch_timeout)
            .map_err(|e| e.to_string())?;
        sock.write_all(&wire).map_err(|e| e.to_string())?;
        // No half-close here: Tor tears the circuit down when it sees the FIN,
        // which throws the response away. `Connection: close` in the request is
        // what ends the response instead.
        let raw = crate::httpf::read_response(&mut sock);
        let parsed = parse_response(&raw);
        if parsed.status == 0 {
            return Err(format!(
                "no usable response from {} ({} bytes: {:?})",
                self.onion,
                raw.len(),
                crate::tlsf::hex_dump(&raw[..raw.len().min(64)])
            ));
        }
        Ok((parsed.status, parsed.body))
    }

    pub fn newnym(&mut self) -> Result<(), TorError> {
        let mut c = Control::connect(self.control, Duration::from_secs(10))?;
        c.authenticate(&self.data_dir)?;
        c.signal("NEWNYM")
    }

    /// Circuit table — the "these really were different paths" evidence.
    pub fn circuits(&mut self) -> Result<Vec<Circuit>, TorError> {
        let mut c = Control::connect(self.control, Duration::from_secs(10))?;
        c.authenticate(&self.data_dir)?;
        c.circuits()
    }

    /// Raw `GETINFO circuit-status` lines: a report can quote the control-port
    /// output its circuit evidence came from.
    pub fn circuit_status_raw(&mut self) -> Result<Vec<String>, TorError> {
        let mut c = Control::connect(self.control, Duration::from_secs(10))?;
        c.authenticate(&self.data_dir)?;
        c.getinfo("circuit-status")
    }

    /// Control-port log of one authenticated session, for the evidence file.
    pub fn control_transcript(&mut self) -> Result<Vec<String>, TorError> {
        let mut c = Control::connect(self.control, Duration::from_secs(10))?;
        c.authenticate(&self.data_dir)?;
        let _ = c.version()?;
        let _ = c.getinfo("circuit-status")?;
        Ok(c.log)
    }

    pub fn stop(&mut self) {
        if let Some(mut ch) = self.child.take() {
            let _ = ch.kill();
            let _ = ch.wait();
        }
    }
}

impl Drop for TorInstance {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Feed a whole reply through the framing scanner.
    fn scan(lines: &[&str]) -> Result<(u16, Vec<String>), TorError> {
        let mut sc = ReplyScanner::default();
        for l in lines {
            if sc.push(l) {
                break;
            }
        }
        sc.finish()
    }

    #[test]
    fn hop_fingerprint_from_all_tor_forms() {
        assert_eq!(
            hop_fingerprint("$0A1B2C3D4E5F60718293A4B5C6D7E8F901234567~guard"),
            Some("0A1B2C3D4E5F60718293A4B5C6D7E8F901234567".to_string())
        );
        assert_eq!(
            hop_fingerprint("8.8.8.8=9A0B1C2D3E4F5061728394A5B6C7D8E9F0123456=exit"),
            Some("9A0B1C2D3E4F5061728394A5B6C7D8E9F0123456".to_string())
        );
        assert_eq!(hop_fingerprint("$AAAA"), None);
    }

    #[test]
    fn circuit_line_modern_tor_format() {
        // tor 0.4.9: <id> <state> <routers> KEY=VALUE ...
        let l = "1 BUILT $4D1C9BA70C884135BD0B8DFA61335F7CE0A87EF6~Killix,$D41AFC78224578E5C5B3C26C2E55778037A52C5B~LeClassique,$141C317F74D92DA44FAA072F6BFD0C98DEFF9066~kramse03 BUILD_FLAGS=NEED_CAPACITY,NEED_UPTIME PURPOSE=GENERAL TIME_CREATED=2026-11-13T03:15:38.902011";
        let c = parse_circuit_line(l).expect("parse");
        assert_eq!(c.id, 1);
        assert_eq!(c.state, "BUILT");
        assert_eq!(c.purpose, "general");
        assert_eq!(c.path.len(), 3);
        assert_eq!(c.build_flags, "NEED_CAPACITY,NEED_UPTIME");
        assert!(c.time_created.starts_with("2026-11-13T03:15"));
        assert_eq!(
            c.exit_fingerprint().as_deref(),
            Some("141C317F74D92DA44FAA072F6BFD0C98DEFF9066")
        );
        assert_eq!(
            c.path_fingerprints()[0],
            "4D1C9BA70C884135BD0B8DFA61335F7CE0A87EF6"
        );
        assert_eq!(c.path_fingerprints().len(), 3);
    }

    #[test]
    fn circuit_line_legacy_format() {
        let l = "4 general ntor - BUILT - 1700000000 1700000001 $0A1B2C3D4E5F60718293A4B5C6D7E8F901234567~guard,8.8.8.8=9A0B1C2D3E4F5061728394A5B6C7D8E9F0123456=exit";
        let c = parse_circuit_line(l).expect("legacy parse");
        assert_eq!(c.id, 4);
        assert_eq!(c.purpose, "general");
        assert_eq!(c.build_type, "ntor");
        assert_eq!(c.state, "BUILT");
        assert_eq!(c.path.len(), 2);
        assert_eq!(
            c.exit_fingerprint().as_deref(),
            Some("9A0B1C2D3E4F5061728394A5B6C7D8E9F0123456")
        );
    }

    #[test]
    fn circuit_line_rend_circuit_parses() {
        let l = "18 BUILT $D5C03C61E3F44A8B766B8B615587025CFD5B9E0C~Playstar04,$644C3216C5A415A1B0C566489B0AD3C5AFF6F81F~artemisRelay,$D449ACD681398217BF669A03C2724C41A96D23D8~mikewillmadeit BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED REND_QUERY=yygr5asx6gpqsjzk TIME_CREATED=2026-11-13T03:33:56.304580";
        let c = parse_circuit_line(l).expect("rend parse");
        assert_eq!(c.purpose, "hs_client_rend");
        assert_eq!(c.state, "BUILT");
        assert_eq!(c.path_fingerprints().len(), 3);
    }

    #[test]
    fn circuit_line_without_routers_or_state() {
        let c = parse_circuit_line("7 general ntor - LAUNDRY -").expect("parse");
        assert_eq!(c.state, "LAUNDRY");
        assert!(c.path.is_empty());
        assert!(c.exit.is_none());
        assert!(parse_circuit_line("circuit-status=").is_none());
        assert!(parse_circuit_line("").is_none());
        assert!(parse_circuit_line("not-a-number BUILT $AAAA").is_none());
    }

    #[test]
    fn reply_scanner_handles_all_three_prefixes() {
        // single line
        let (code, out) = scan(&["250 OK"]).unwrap();
        assert_eq!(code, 250);
        assert_eq!(out, vec!["OK".to_string()]);
        // dash continuation
        let (code, out) = scan(&["250-version=0.4.9.14", "250 OK"]).unwrap();
        assert_eq!(code, 250);
        assert_eq!(out, vec!["version=0.4.9.14", "OK"]);
        // dot-terminated table (what circuit-status really looks like)
        let (code, out) = scan(&[
            "250+circuit-status=",
            "1 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~=a PURPOSE=GENERAL",
            ".",
            "250 OK",
        ])
        .unwrap();
        assert_eq!(code, 250);
        assert_eq!(out[0], "circuit-status=");
        assert_eq!(
            out[1],
            "1 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~=a PURPOSE=GENERAL"
        );
        let c = parse_circuit_line(&out[1]).expect("circuit from a wire line");
        assert_eq!(c.id, 1);
        assert_eq!(c.state, "BUILT");
        // 650 async events are skipped
        let (code, _) = scan(&[
            "650 NOTICE Bootstrap",
            "250+circuit-status=",
            "650 NOTICE still async",
            "2 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~=a",
            ".",
            "250 OK",
        ])
        .unwrap();
        assert_eq!(code, 250);
    }

    #[test]
    fn reply_errors_are_errors() {
        let e = scan(&["552 Unrecognized key \"bogus\"", "552 END"]).unwrap_err();
        assert_eq!(e.stage, "command");
        assert!(e.detail.contains("Unrecognized"));
        let e = scan(&[]).unwrap_err();
        assert_eq!(e.stage, "read");
        let e = scan(&["514 Authentication required."]).unwrap_err();
        assert_eq!(e.stage, "command");
    }

    /// A fake control port: answers every command a client sends on a
    /// connection, the way a real one does, and records the commands.
    fn fake_control_server() -> (SocketAddr, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            loop {
                let Ok((mut c, _)) = listener.accept() else {
                    break;
                };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut reader = std::io::BufReader::new(c.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                        let cmd = line.trim_end_matches(['\r', '\n']).to_string();
                        if cmd.is_empty() {
                            continue;
                        }
                        let _ = tx.send(cmd.clone());
                        let reply = if cmd.starts_with("PROTOCOLINFO") {
                            "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"control_auth\"\r\n250-VERSION Tor=\"0.4.9.14\"\r\n250 OK\r\n".to_string()
                        } else if cmd.starts_with("AUTHENTICATE") {
                            if cmd.len() < 20 {
                                "515 Authentication failed: Wrong length on authentication cookie.\r\n".to_string()
                            } else {
                                "250 OK\r\n".to_string()
                            }
                        } else if cmd == "GETINFO version" {
                            "250-version=0.4.9.14\r\n250 OK\r\n".to_string()
                        } else if cmd == "GETINFO circuit-status" {
                            // tor 0.4.9 answers this key verbatim between `+` and `.`
                            "250+circuit-status=\r\n1 BUILT $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~=a,8.8.8.8=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=b BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-11-13T00:00:00\r\n.\r\n250 OK\r\n".to_string()
                        } else if cmd.starts_with("GETINFO") {
                            format!(
                                "552 Unrecognized key \"{}\"\r\n",
                                cmd.strip_prefix("GETINFO").unwrap_or("").trim()
                            )
                        } else if cmd.starts_with("SIGNAL") {
                            "250 OK\r\n".to_string()
                        } else if cmd == "QUIT" {
                            let _ = c.write_all(b"250 OK\r\n");
                            let _ = c.flush();
                            break;
                        } else {
                            format!("510 Unknown command \"{cmd}\"\r\n")
                        };
                        if c.write_all(reply.as_bytes()).is_err() {
                            break;
                        }
                        let _ = c.flush();
                    }
                    let _ = c.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        (addr, rx)
    }

    #[test]
    fn control_client_against_a_fake_server() {
        let (addr, rx) = fake_control_server();
        let mut c = Control::connect(addr, Duration::from_secs(5)).expect("connect+protocolinfo");
        assert!(rx.recv().unwrap().starts_with("PROTOCOLINFO"));
        assert!(c.protocol_info.iter().any(|l| l.contains("AUTH")));
        let dir = std::env::temp_dir().join(format!("hardvoy-cookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("control_auth"), vec![7u8; 32]).unwrap();
        // PROTOCOLINFO here advertises a relative COOKIEFILE, which resolves
        // against the data directory we handed Tor
        c.authenticate(&dir).expect("cookie auth");
        assert!(rx.recv().unwrap().starts_with("AUTHENTICATE"));
        assert_eq!(c.version().unwrap(), "0.4.9.14");
        assert!(rx.recv().unwrap().contains("GETINFO version"));
        c.signal("NEWNYM").expect("newnym");
        assert_eq!(rx.recv().unwrap(), "SIGNAL NEWNYM");
        assert!(c.log.iter().any(|l| l.starts_with("PROTOCOLINFO 1 ->")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn control_client_reads_circuits_from_the_fake_server() {
        let (addr, _rx) = fake_control_server();
        let mut c = Control::connect(addr, Duration::from_secs(5)).expect("connect");
        let cs = c.circuits().expect("circuits");
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].state, "BUILT");
        assert_eq!(cs[0].path_fingerprints().len(), 2);
    }

    #[test]
    fn cookie_file_that_is_the_wrong_length_is_reported() {
        let (addr, _rx) = fake_control_server();
        let mut c = Control::connect(addr, Duration::from_secs(5)).expect("connect");
        let dir = std::env::temp_dir().join(format!("hardvoy-badcookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("control_auth"), b"short").unwrap();
        let e = c.authenticate(&dir).unwrap_err();
        assert_eq!(e.stage, "cookie-file");
        assert!(e.detail.contains("expected 32 bytes, got 5"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cookie_file_is_reported_not_a_panic() {
        let (addr, _rx) = fake_control_server();
        let mut c = Control::connect(addr, Duration::from_secs(5)).expect("connect");
        let e = c
            .authenticate(&PathBuf::from("/nonexistent-hardvoy-dir"))
            .unwrap_err();
        assert_eq!(e.stage, "cookie-file");
    }

    #[test]
    fn control_connect_to_a_closed_port_reports_cleanly() {
        let e = Control::connect("127.0.0.1:1".parse().unwrap(), Duration::from_millis(300))
            .unwrap_err();
        assert_eq!(e.stage, "connect");
    }

    #[test]
    fn cookie_path_from_protocolinfo_is_used() {
        let dir = std::env::temp_dir().join(format!("hardvoy-cookiepath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie = dir.join("control_auth");
        std::fs::write(&cookie, vec![3u8; 32]).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let cookie_disp = cookie.display().to_string();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 512];
            let _ = c.read(&mut buf).unwrap();
            let reply =
                format!("250-AUTH METHODS=COOKIE COOKIEFILE=\"{cookie_disp}\"\r\n250 OK\r\n");
            let _ = c.write_all(reply.as_bytes());
            let _ = c.flush();
            let _ = c.read(&mut buf).unwrap();
            let _ = c.write_all(b"250 OK\r\n");
            let _ = c.flush();
        });
        let mut c = Control::connect(addr, Duration::from_secs(5)).expect("connect");
        c.authenticate(&PathBuf::from("/nonexistent"))
            .expect("auth by protocolinfo path");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
