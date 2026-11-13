//! SOCKS5 client (RFC 1928 + RFC 1929 username/password).
//!
//! hardvoy needs this for two reasons: to reach the lab through Tor's SOCKS
//! proxy, and to prove that a probe really used the egress path it claims.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocksError {
    Greeting { got: Vec<u8> },
    NeedsAuth,
    AuthFailed,
    Refused { code: u8, meaning: String },
    BadAddress,
    Truncated(&'static str),
    Io(String),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksError::Greeting { got } => write!(f, "bad SOCKS5 greeting: {got:02x?}"),
            SocksError::NeedsAuth => write!(f, "SOCKS5 server requires authentication"),
            SocksError::AuthFailed => write!(f, "SOCKS5 username/password authentication failed"),
            SocksError::Refused { code, meaning } => {
                write!(f, "SOCKS5 connect refused (reply 0x{code:02x}: {meaning})")
            }
            SocksError::BadAddress => write!(f, "SOCKS5 server returned an unusable bound address"),
            SocksError::Truncated(w) => write!(f, "SOCKS5 handshake truncated at {w}"),
            SocksError::Io(e) => write!(f, "SOCKS5 io error: {e}"),
        }
    }
}
impl std::error::Error for SocksError {}

/// SOCKS5 reply codes, spelled out because Tor returns them for real failures
/// and a report should say which one it saw.
pub fn reply_meaning(code: u8) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused by destination host",
        0x06 => "TTL expired (Tor: circuit too old, retry)",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksAuth {
    pub user: String,
    pub pass: String,
}

/// Connect to `host:port` through the SOCKS5 proxy at `proxy`.
///
/// Hostnames (including `.onion`) are sent verbatim with ATYP=0x03, which is
/// what makes remote resolution — and therefore a real Tor circuit — happen.
pub fn connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<&SocksAuth>,
    timeout: Duration,
) -> Result<TcpStream, SocksError> {
    let mut s =
        TcpStream::connect_timeout(&proxy, timeout).map_err(|e| SocksError::Io(e.to_string()))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();

    // greeting
    let mut methods = vec![0x00u8];
    if auth.is_some() {
        methods.push(0x02);
    }
    let mut greet = vec![0x05u8, methods.len() as u8];
    greet.extend_from_slice(&methods);
    write_all(&mut s, &greet)?;
    let mut rep = [0u8; 2];
    read_exact(&mut s, &mut rep)?;
    if rep[0] != 0x05 {
        return Err(SocksError::Greeting { got: rep.to_vec() });
    }
    if rep[1] == 0xFF {
        return Err(SocksError::Greeting { got: rep.to_vec() });
    }
    if rep[1] == 0x02 {
        let a = auth.ok_or(SocksError::NeedsAuth)?;
        let mut sub = vec![0x01u8];
        sub.push(a.user.len() as u8);
        sub.extend_from_slice(a.user.as_bytes());
        sub.push(a.pass.len() as u8);
        sub.extend_from_slice(a.pass.as_bytes());
        write_all(&mut s, &sub)?;
        let mut ur = [0u8; 2];
        read_exact(&mut s, &mut ur)?;
        if ur[0] != 0x01 || ur[1] != 0x00 {
            return Err(SocksError::AuthFailed);
        }
    } else if rep[1] != 0x00 {
        return Err(SocksError::Greeting { got: rep.to_vec() });
    }

    // request
    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(SocksError::BadAddress);
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    write_all(&mut s, &req)?;

    let mut hdr = [0u8; 4];
    read_exact(&mut s, &mut hdr)?;
    if hdr[0] != 0x05 {
        return Err(SocksError::Greeting { got: hdr.to_vec() });
    }
    if hdr[1] != 0x00 {
        return Err(SocksError::Refused {
            code: hdr[1],
            meaning: reply_meaning(hdr[1]).to_string(),
        });
    }
    // drain the bound address
    match hdr[3] {
        0x01 => drain(&mut s, 6)?,
        0x03 => {
            let mut l = [0u8; 1];
            read_exact(&mut s, &mut l)?;
            drain(&mut s, l[0] as usize + 2)?;
        }
        0x04 => drain(&mut s, 18)?,
        _ => return Err(SocksError::BadAddress),
    }
    Ok(s)
}

fn write_all(s: &mut TcpStream, b: &[u8]) -> Result<(), SocksError> {
    s.write_all(b).map_err(|e| SocksError::Io(e.to_string()))
}

fn read_exact(s: &mut TcpStream, b: &mut [u8]) -> Result<(), SocksError> {
    let mut n = 0;
    while n < b.len() {
        match s.read(&mut b[n..]) {
            Ok(0) => return Err(SocksError::Truncated("end of stream")),
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SocksError::Io(e.to_string())),
        }
    }
    Ok(())
}

fn drain(s: &mut TcpStream, n: usize) -> Result<(), SocksError> {
    let mut buf = vec![0u8; n];
    read_exact(s, &mut buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A stub SOCKS5 server: checks the request and echoes bytes back.
    fn stub(behavior: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                seen2.fetch_add(1, Ordering::SeqCst);
                let mut g = [0u8; 2];
                read_exact(&mut c, &mut g).unwrap();
                let nmethods = g[1] as usize;
                let mut methods = vec![0u8; nmethods];
                read_exact(&mut c, &mut methods).unwrap();
                if behavior == "needs-auth" {
                    c.write_all(&[0x05, 0x02]).unwrap();
                    let mut v = [0u8; 1];
                    read_exact(&mut c, &mut v).unwrap();
                    let ul = {
                        let mut x = [0u8; 1];
                        read_exact(&mut c, &mut x).unwrap();
                        x[0] as usize
                    };
                    let mut user = vec![0u8; ul];
                    read_exact(&mut c, &mut user).unwrap();
                    let pl = {
                        let mut x = [0u8; 1];
                        read_exact(&mut c, &mut x).unwrap();
                        x[0] as usize
                    };
                    let mut pass = vec![0u8; pl];
                    read_exact(&mut c, &mut pass).unwrap();
                    let ok = user == b"hardvoy" && pass == b"secret";
                    c.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).unwrap();
                    if !ok {
                        continue;
                    }
                } else {
                    c.write_all(&[0x05, 0x00]).unwrap();
                }
                let mut r = [0u8; 4];
                read_exact(&mut c, &mut r).unwrap();
                if behavior == "refuse" {
                    c.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .unwrap();
                    continue;
                }
                if behavior == "garbage" {
                    c.write_all(b"hi there friend").unwrap();
                    continue;
                }
                let atyp = r[3];
                match atyp {
                    0x03 => {
                        let mut l = [0u8; 1];
                        read_exact(&mut c, &mut l).unwrap();
                        let mut host = vec![0u8; l[0] as usize];
                        read_exact(&mut c, &mut host).unwrap();
                        let mut port = [0u8; 2];
                        read_exact(&mut c, &mut port).unwrap();
                        // domain names only: proves remote resolution
                        if host == b"hardvoy.onion" {
                            c.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                                .unwrap();
                            let mut echo = Vec::new();
                            c.read_to_end(&mut echo).unwrap();
                            c.write_all(&echo).unwrap();
                        } else {
                            c.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .unwrap();
                        }
                    }
                    _ => {
                        c.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .unwrap();
                    }
                }
            }
        });
        (addr, seen)
    }

    #[test]
    fn connects_a_domain_and_echoes() {
        let (proxy, seen) = stub("ok");
        let mut s =
            connect(proxy, "hardvoy.onion", 80, None, Duration::from_secs(3)).expect("connect");
        s.write_all(b"ping").unwrap();
        // half-close so the stub sees end of request and closes the tunnel
        s.shutdown(Shutdown::Write).unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        assert_eq!(b, b"ping");
        assert_eq!(seen.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unknown_domain_is_refused_by_the_stub() {
        let (proxy, _) = stub("ok");
        let e = connect(proxy, "example.com", 80, None, Duration::from_secs(3)).unwrap_err();
        assert!(matches!(e, SocksError::Refused { code: 0x04, .. }));
    }

    #[test]
    fn refused_codes_are_explained() {
        let (proxy, _) = stub("refuse");
        let e = connect(proxy, "hardvoy.onion", 80, None, Duration::from_secs(3)).unwrap_err();
        match e {
            SocksError::Refused { code, meaning } => {
                assert_eq!(code, 0x05);
                assert!(meaning.contains("refused"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn username_password_auth_works_and_fails_honestly() {
        let (proxy, _) = stub("needs-auth");
        let good = SocksAuth {
            user: "hardvoy".into(),
            pass: "secret".into(),
        };
        let mut s = connect(
            proxy,
            "hardvoy.onion",
            80,
            Some(&good),
            Duration::from_secs(3),
        )
        .expect("auth ok");
        s.write_all(b"yo").unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        assert_eq!(b, b"yo");

        let bad = SocksAuth {
            user: "nope".into(),
            pass: "wrong".into(),
        };
        let e = connect(
            proxy,
            "hardvoy.onion",
            80,
            Some(&bad),
            Duration::from_secs(3),
        )
        .unwrap_err();
        assert!(matches!(e, SocksError::AuthFailed));

        // and without credentials the server's demand is reported, not hidden
        let e = connect(proxy, "hardvoy.onion", 80, None, Duration::from_secs(3)).unwrap_err();
        assert!(matches!(e, SocksError::NeedsAuth));
    }

    #[test]
    fn garbage_greeting_is_a_clean_error() {
        let (proxy, _) = stub("garbage");
        let e = connect(proxy, "hardvoy.onion", 80, None, Duration::from_secs(3)).unwrap_err();
        assert!(
            matches!(
                e,
                SocksError::Greeting { .. } | SocksError::Refused { .. } | SocksError::BadAddress
            ),
            "unexpected error kind: {e:?}"
        );
    }

    #[test]
    fn dead_proxy_reports_io_error() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let e = connect(addr, "hardvoy.onion", 80, None, Duration::from_secs(2)).unwrap_err();
        assert!(matches!(e, SocksError::Io(_)), "got {e:?}");
    }

    #[test]
    fn reply_codes_have_meanings() {
        for c in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99] {
            assert!(!reply_meaning(c).is_empty());
        }
        assert!(reply_meaning(0x06).contains("circuit"));
    }
}
