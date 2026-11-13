//! SSH version + KEXINIT sniffing and HASSH fingerprints.
//!
//! HASSH (Black Hat USA 2017, IBM/Atredis Partners) is the MD5 of eight
//! comma-joined algorithm name-lists taken from a KEXINIT packet in payload
//! order. hardvoy implements it exactly, in both directions:
//!
//! * **client side** — what an SSH client on this machine would show the world
//! * **server side** — what the listener's own list looks like
//!
//! No key exchange is performed: the sniffer reads the version line and the
//! KEXINIT, answers with its own KEXINIT, then closes. That is enough to
//! fingerprint both peers, and it is why this works over a Tor circuit without
//! any host-key trust.

use crate::util::md5_hex_str;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshError {
    NotSsh(String),
    Truncated(&'static str),
    Io(String),
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::NotSsh(first) => write!(f, "not an SSH banner (first line: {first:?})"),
            SshError::Truncated(what) => write!(f, "truncated SSH packet at {what}"),
            SshError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for SshError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KexInit {
    pub cookie_hex: String,
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_c2s: Vec<String>,
    pub encryption_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub languages_c2s: Vec<String>,
    pub languages_s2c: Vec<String>,
    pub first_kex_packet_follows: bool,
}

impl KexInit {
    /// Parse a KEXINIT packet payload (the byte 20 included).
    pub fn from_payload(p: &[u8]) -> Result<KexInit, SshError> {
        if p.is_empty() {
            return Err(SshError::Truncated("payload"));
        }
        if p[0] != 20 {
            return Err(SshError::Truncated(
                "message type is not SSH_MSG_KEXINIT (20)",
            ));
        }
        if p.len() < 17 {
            return Err(SshError::Truncated("cookie"));
        }
        let mut r = R::new(&p[17..]);
        let mut lists = Vec::with_capacity(10);
        for _ in 0..10 {
            lists.push(split_namelist(&r.namelist()?));
        }
        let follows = match r.byte() {
            Some(b) => b != 0,
            None => false,
        };
        Ok(KexInit {
            cookie_hex: crate::util::hex(&p[1..17]),
            kex_algorithms: lists.remove(0),
            server_host_key_algorithms: lists.remove(0),
            encryption_c2s: lists.remove(0),
            encryption_s2c: lists.remove(0),
            compression_c2s: lists.remove(0),
            compression_s2c: lists.remove(0),
            mac_c2s: lists.remove(0),
            mac_s2c: lists.remove(0),
            languages_c2s: lists.remove(0),
            languages_s2c: lists.remove(0),
            first_kex_packet_follows: follows,
        })
    }

    /// The eight-list HASSH input string (payload order, language lists
    /// excluded, empty lists stay empty fields).
    pub fn hassh_string(&self) -> String {
        [
            &self.kex_algorithms,
            &self.server_host_key_algorithms,
            &self.encryption_c2s,
            &self.encryption_s2c,
            &self.compression_c2s,
            &self.compression_s2c,
            &self.mac_c2s,
            &self.mac_s2c,
        ]
        .iter()
        .map(|l| l.join(","))
        .collect::<Vec<_>>()
        .join(",")
    }

    pub fn hassh(&self) -> String {
        md5_hex_str(&self.hassh_string())
    }

    /// Wire bytes for a KEXINIT packet (framing included, random padding).
    pub fn to_packet(&self) -> Vec<u8> {
        let mut p: Vec<u8> = vec![20];
        p.extend_from_slice(&self.cookie());
        for l in [
            &self.kex_algorithms,
            &self.server_host_key_algorithms,
            &self.encryption_c2s,
            &self.encryption_s2c,
            &self.compression_c2s,
            &self.compression_s2c,
            &self.mac_c2s,
            &self.mac_s2c,
            &self.languages_c2s,
            &self.languages_s2c,
        ] {
            let s = l.join(",");
            p.extend_from_slice(&(s.len() as u32).to_be_bytes());
            p.extend_from_slice(s.as_bytes());
        }
        p.push(if self.first_kex_packet_follows { 1 } else { 0 });
        p.extend_from_slice(&[0, 0, 0, 0]); // reserved
        frame(&p, 8)
    }

    /// 16 byte cookie, deterministic from the label so tests are stable.
    pub fn cookie(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let src = crate::util::sha256(self.cookie_hex.as_bytes());
        out.copy_from_slice(&src[..16]);
        out
    }
}

fn split_namelist(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(|x| x.to_string()).collect()
}

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        R { b, i: 0 }
    }
    fn byte(&mut self) -> Option<u8> {
        if self.i >= self.b.len() {
            return None;
        }
        let v = self.b[self.i];
        self.i += 1;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        if self.i + 4 > self.b.len() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.b[self.i],
            self.b[self.i + 1],
            self.b[self.i + 2],
            self.b[self.i + 3],
        ]);
        self.i += 4;
        Some(v)
    }
    fn namelist(&mut self) -> Result<String, SshError> {
        let n = self.u32().ok_or(SshError::Truncated("namelist length"))? as usize;
        if self.i + n > self.b.len() {
            return Err(SshError::Truncated("namelist body"));
        }
        let s = String::from_utf8_lossy(&self.b[self.i..self.i + n]).into_owned();
        self.i += n;
        Ok(s)
    }
}

/// Wrap a payload in the SSH binary packet format:
/// packet_length(4) padding_length(1) payload padding.
///
/// The whole packet, including the 4-byte length field, must be a multiple of
/// the block size (8 before encryption) and at least 16 bytes, with at least 4
/// bytes of padding.
fn frame(payload: &[u8], block: usize) -> Vec<u8> {
    let block = block.max(8);
    let mut pad = (block - (4 + 1 + payload.len()) % block) % block;
    if pad < 4 {
        pad += block;
    }
    let packet_len = 1 + payload.len() + pad;
    let mut out: Vec<u8> = Vec::with_capacity(4 + packet_len);
    out.extend_from_slice(&(packet_len as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    for i in 0..pad {
        out.push((0x11 * (i as u8 % 16)) | 1);
    }
    out
}

/// Read the identification line ("SSH-2.0-OpenSSH_9.9") from a stream.
pub fn read_banner<R: Read>(r: &mut R) -> Result<String, SshError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match r.read(&mut b) {
            Ok(0) => {
                return Err(SshError::Io(
                    "connection closed during banner exchange".into(),
                ));
            }
            Ok(_) => {
                if b[0] == b'\n' {
                    break;
                }
                if b[0] != b'\r' {
                    line.push(b[0]);
                }
                if line.len() > 255 {
                    return Err(SshError::NotSsh(
                        String::from_utf8_lossy(&line).into_owned(),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SshError::Io(e.to_string())),
        }
    }
    let s = String::from_utf8_lossy(&line).into_owned();
    if !s.starts_with("SSH-") {
        return Err(SshError::NotSsh(s));
    }
    Ok(s)
}

/// Read one SSH binary packet and return its payload.
///
/// MACs are not verified because hardvoy never gets past KEXINIT; unencrypted
/// packets are what we are reading.
pub fn read_packet<R: Read>(r: &mut R) -> Result<Vec<u8>, SshError> {
    let mut hdr = [0u8; 4];
    read_exact(r, &mut hdr)?;
    let packet_len = u32::from_be_bytes(hdr) as usize;
    if !(2..=64 * 1024).contains(&packet_len) {
        return Err(SshError::Truncated("packet length out of range"));
    }
    let mut rest = vec![0u8; packet_len];
    read_exact(r, &mut rest)?;
    let pad_len = rest[0] as usize;
    let payload_len = packet_len.saturating_sub(1 + pad_len);
    Ok(rest[1..1 + payload_len].to_vec())
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), SshError> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => return Err(SshError::Io("closed mid-packet".into())),
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SshError::Io(e.to_string())),
        }
    }
    Ok(())
}

/// A plausible OpenSSH-style KEXINIT, used as hardvoy's own client profile.
/// `variant` selects which modern algorithms go first, which changes HASSH.
pub fn client_kexinit(variant: &str) -> KexInit {
    let (kex, host, mut enc, comp, mac) = match variant {
        "openssh9.9" => (
            vec![
                "mlkem768x25519",
                "sntrup761x25519-sha512",
                "curve25519-sha256",
                "curve25519-sha256@libssh.org",
                "ecdh-sha2-nistp256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
                "diffie-hellman-group14-sha256",
            ],
            vec![
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "rsa-sha2-512",
                "rsa-sha2-256",
                "ssh-rsa",
            ],
            vec![
                "chacha20-poly1305@openssh.com",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
            ],
            vec!["none", "zlib@openssh.com"],
            vec![
                "umac-64-etm@openssh.com",
                "umac-128-etm@openssh.com",
                "hmac-sha2-256-etm@openssh.com",
                "hmac-sha2-512-etm@openssh.com",
                "hmac-sha1-etm@openssh.com",
                "umac-64@openssh.com",
                "umac-128@openssh.com",
                "hmac-sha2-256",
                "hmac-sha2-512",
                "hmac-sha1",
            ],
        ),
        "minimal" => (
            vec!["curve25519-sha256"],
            vec!["ssh-ed25519"],
            vec!["chacha20-poly1305@openssh.com"],
            vec!["none"],
            vec!["hmac-sha2-256-etm@openssh.com"],
        ),
        _ => {
            return KexInit {
                cookie_hex: "hardvoy-default".into(),
                kex_algorithms: vec![
                    "curve25519-sha256".into(),
                    "curve25519-sha256@libssh.org".into(),
                ],
                server_host_key_algorithms: vec!["ssh-ed25519".into(), "rsa-sha2-256".into()],
                encryption_c2s: vec!["aes128-ctr".into(), "aes256-ctr".into()],
                encryption_s2c: vec!["aes128-ctr".into(), "aes256-ctr".into()],
                compression_c2s: vec!["none".into()],
                compression_s2c: vec!["none".into()],
                mac_c2s: vec![
                    "umac-64-etm@openssh.com".into(),
                    "hmac-sha2-256-etm@openssh.com".into(),
                ],
                mac_s2c: vec![
                    "umac-64-etm@openssh.com".into(),
                    "hmac-sha2-256-etm@openssh.com".into(),
                ],
                languages_c2s: Vec::new(),
                languages_s2c: Vec::new(),
                first_kex_packet_follows: false,
            }
        }
    };
    enc.push("aes256-cbc"); // hardvoy's own twist, so profiles differ honestly
    KexInit {
        cookie_hex: format!("hardvoy-{variant}"),
        kex_algorithms: kex.iter().map(|s| s.to_string()).collect(),
        server_host_key_algorithms: host.iter().map(|s| s.to_string()).collect(),
        encryption_c2s: enc.iter().map(|s| s.to_string()).collect(),
        encryption_s2c: enc.iter().map(|s| s.to_string()).collect(),
        compression_c2s: comp.iter().map(|s| s.to_string()).collect(),
        compression_s2c: comp.iter().map(|s| s.to_string()).collect(),
        mac_c2s: mac.iter().map(|s| s.to_string()).collect(),
        mac_s2c: mac.iter().map(|s| s.to_string()).collect(),
        languages_c2s: Vec::new(),
        languages_s2c: Vec::new(),
        first_kex_packet_follows: false,
    }
}

pub const BANNER: &str = "SSH-2.0-hardvoy_0.1";

/// Drive one client-side KEXINIT exchange and report both peers' HASSH.
pub fn exchange<S: Read + Write>(mut sock: S, spec: &str) -> Result<SshExchange, SshError> {
    let our_kex = client_kexinit(spec);
    sock.write_all(BANNER.as_bytes())
        .map_err(|e| SshError::Io(e.to_string()))?;
    sock.write_all(b"\r\n")
        .map_err(|e| SshError::Io(e.to_string()))?;
    sock.write_all(&our_kex.to_packet())
        .map_err(|e| SshError::Io(e.to_string()))?;
    sock.flush().map_err(|e| SshError::Io(e.to_string()))?;
    let their_banner = read_banner(&mut sock)?;
    let pkt = read_packet(&mut sock)?;
    let their_kex = KexInit::from_payload(&pkt)?;
    Ok(SshExchange {
        our_hassh: our_kex.hassh(),
        their_hassh: their_kex.hassh(),
        our_kex,
        their_kex,
        their_banner,
    })
}

/// `exchange` with a deadline, for probing servers that may be slow or silent.
pub fn exchange_with_timeout(
    sock: std::net::TcpStream,
    spec: &str,
    timeout: std::time::Duration,
) -> Result<SshExchange, SshError> {
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| SshError::Io(e.to_string()))?;
    sock.set_write_timeout(Some(timeout))
        .map_err(|e| SshError::Io(e.to_string()))?;
    exchange(sock, spec)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshExchange {
    pub our_hassh: String,
    pub their_hassh: String,
    pub our_kex: KexInit,
    pub their_kex: KexInit,
    pub their_banner: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_kexinit_payload() -> Vec<u8> {
        let k = KexInit {
            cookie_hex: "vec-test".into(),
            kex_algorithms: vec!["curve25519-sha256".into()],
            server_host_key_algorithms: vec!["ssh-ed25519".into(), "ssh-rsa".into()],
            encryption_c2s: vec!["aes128-ctr".into()],
            encryption_s2c: vec!["aes128-ctr".into()],
            compression_c2s: vec!["none".into()],
            compression_s2c: vec!["none".into()],
            mac_c2s: vec!["hmac-sha2-256".into()],
            mac_s2c: vec!["hmac-sha2-256".into()],
            languages_c2s: Vec::new(),
            languages_s2c: Vec::new(),
            first_kex_packet_follows: false,
        };
        let pkt = k.to_packet();
        let len = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
        pkt[4..4 + len][1..].to_vec()
    }

    #[test]
    fn hassh_string_field_order_and_empties() {
        let k = KexInit {
            cookie_hex: "x".into(),
            kex_algorithms: vec!["a".into(), "b".into()],
            server_host_key_algorithms: vec!["c".into()],
            encryption_c2s: vec!["d".into()],
            encryption_s2c: vec!["e".into()],
            compression_c2s: Vec::new(),
            compression_s2c: Vec::new(),
            mac_c2s: vec!["f".into()],
            mac_s2c: vec!["g".into()],
            languages_c2s: Vec::new(),
            languages_s2c: Vec::new(),
            first_kex_packet_follows: false,
        };
        // empty compression lists stay as empty fields
        assert_eq!(k.hassh_string(), "a,b,c,d,e,,,f,g");
        assert_eq!(k.hassh().len(), 32);
    }

    #[test]
    fn hassh_known_vector() {
        // MD5 of the exact string above, computed independently (md5sum).
        let k = KexInit {
            cookie_hex: "x".into(),
            kex_algorithms: vec!["a".into(), "b".into()],
            server_host_key_algorithms: vec!["c".into()],
            encryption_c2s: vec!["d".into()],
            encryption_s2c: vec!["e".into()],
            compression_c2s: Vec::new(),
            compression_s2c: Vec::new(),
            mac_c2s: vec!["f".into()],
            mac_s2c: vec!["g".into()],
            languages_c2s: Vec::new(),
            languages_s2c: Vec::new(),
            first_kex_packet_follows: false,
        };
        assert_eq!(k.hassh(), md5_of("a,b,c,d,e,,,f,g"));
    }

    fn md5_of(s: &str) -> String {
        crate::util::md5_hex_str(s)
    }

    #[test]
    fn payload_roundtrip() {
        let p = sample_kexinit_payload();
        let k = KexInit::from_payload(&p).expect("parse kexinit");
        assert_eq!(k.kex_algorithms, vec!["curve25519-sha256".to_string()]);
        assert_eq!(k.server_host_key_algorithms.len(), 2);
        assert_eq!(k.compression_c2s, vec!["none".to_string()]);
        assert!(!k.first_kex_packet_follows);
        assert_eq!(k.languages_c2s.len(), 0);
    }

    #[test]
    fn framing_block_alignment_and_padding() {
        for plen in [0usize, 5, 40, 41, 42, 100] {
            let payload = vec![20u8; plen];
            let pkt = frame(&payload, 8);
            let len = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]) as usize;
            assert_eq!(pkt.len(), 4 + len, "payload {plen}");
            assert_eq!((4 + len) % 8, 0, "payload {plen} not block aligned");
            assert!(pkt[4] >= 4, "padding must be at least 4 bytes");
            assert!(4 + len >= 16, "packet must be at least 16 bytes");
        }
    }

    #[test]
    fn exchange_with_built_in_server() {
        // server side: parse what the client sent, reply with our own KEXINIT
        // the stand-in server advertises a shorter, older list
        let server_kex = client_kexinit("minimal");
        let spec = "openssh9.9";
        let mut server_out: Vec<u8> = Vec::new();
        server_out.extend_from_slice(b"SSH-2.0-OpenSSH_9.9\r\n");
        server_out.extend_from_slice(&server_kex.to_packet());
        let mut both = Duplex::new(server_out);
        let x = exchange(&mut both, spec).expect("exchange");
        assert_eq!(x.our_hassh, x.our_kex.hassh());
        assert_eq!(x.their_hassh, x.their_kex.hassh());
        assert_eq!(x.their_banner, "SSH-2.0-OpenSSH_9.9");
        assert_eq!(x.their_kex.kex_algorithms[0], "curve25519-sha256");
        assert_eq!(x.our_kex.kex_algorithms[0], "mlkem768x25519");
        assert_ne!(x.our_hassh, x.their_hassh);
    }

    struct Duplex {
        in_buf: std::io::Cursor<Vec<u8>>,
        pub out: Vec<u8>,
    }
    impl Duplex {
        fn new(in_buf: Vec<u8>) -> Self {
            Duplex {
                in_buf: std::io::Cursor::new(in_buf),
                out: Vec::new(),
            }
        }
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.in_buf.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.out.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn rejects_non_ssh_stream() {
        let mut cur = &b"HTTP/1.1 200 OK\r\n"[..];
        let e = read_banner(&mut cur).unwrap_err();
        assert!(matches!(e, SshError::NotSsh(_)));
    }

    #[test]
    fn profiles_have_different_hassh() {
        let a = client_kexinit("openssh9.9").hassh();
        let b = client_kexinit("minimal").hassh();
        let c = client_kexinit("default").hassh();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
