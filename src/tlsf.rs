//! TLS ClientHello: sniffing, parsing, fingerprinting, and building.
//!
//! Two halves:
//!
//! * `ClientHello::from_record_stream` reads raw bytes off a socket until the
//!   whole ClientHello handshake message has been reassembled, which is how
//!   hardvoy's TLS sniffer captures what a browser actually put on the wire.
//! * `HelloSpec` builds a ClientHello from an explicit specification, so
//!   hardvoy can also measure the fingerprint it produces itself and check
//!   that an egress path leaves the hello byte-for-byte intact.
//!
//! Fingerprint algorithms implemented (see `docs/FINGERPRINTS.md`):
//!
//! * **JA3** — MD5 over `version,ciphers,extensions,signature_algorithms,
//!   ec_point_formats` (Salesforce JA3 definition; GREASE values excluded).
//! * **JA4 / JA4TLS** — FoxIO definition: protocol char, highest version,
//!   integrity mode, cipher/extension counts, ALPN first+last character,
//!   base32(SHA-256[12]) of sorted ciphers, base32(SHA-256[12]) of sorted
//!   extensions plus ALPN, and the SNI.
//! * **hardvoy wire summary** — an ordering-preserving summary in the spirit
//!   of Akamai's TLS profile format (extension order, cipher order, ALPN),
//!   i.e. exactly what an IDS sees before any encryption.

use crate::util::{b32_trunc, first_last, hex, md5_hex_str, sha256};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_EC_POINT_FORMATS: u16 = 11;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_SUPPORTED_GROUPS: u16 = 43;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const EXT_SUPPORTED_VERSIONS: u16 = 47;
pub const EXT_KEY_SHARE: u16 = 51;

const MAX_RECORD_LEN: usize = 16_384 + 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    NotTlsRecord(u8),
    BadRecordVersion(u16),
    RecordTooLong(usize),
    ShortHandshake(&'static str),
    WrongHandshakeType(u8),
    Truncated(&'static str),
    Io(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::NotTlsRecord(b) => write!(
                f,
                "first byte is 0x{b:02x}, not a TLS handshake record (0x16)"
            ),
            TlsError::BadRecordVersion(v) => write!(f, "unexpected record version 0x{v:04x}"),
            TlsError::RecordTooLong(n) => {
                write!(f, "TLS record length {n} exceeds the allowed maximum")
            }
            TlsError::ShortHandshake(what) => write!(f, "truncated handshake: {what}"),
            TlsError::WrongHandshakeType(t) => write!(
                f,
                "handshake type is 0x{t:02x}, expected ClientHello (0x01)"
            ),
            TlsError::Truncated(what) => write!(f, "ClientHello truncated at {what}"),
            TlsError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}
impl std::error::Error for TlsError {}

/// True for TLS GREASE code points (RFC 8701): `xaxa` with matching nibbles.
pub fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    // RFC 8701: every GREASE code point is 0x?a?a - both low nibbles are 0xa
    // and the two high nibbles are equal.
    hi & 0x0f == 0x0a && lo & 0x0f == 0x0a && (hi >> 4) == (lo >> 4)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub id: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    pub record_version: u16,
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compressions: Vec<u8>,
    pub extensions: Vec<Extension>,
    /// Exact bytes that made up the handshake message body (no record headers).
    pub body_len: usize,
}

impl ClientHello {
    /// Read TLS records from `r` until one complete ClientHello message is
    /// reassembled. Returns the parsed hello plus every raw byte consumed, so
    /// a caller may replay them into a real TLS stack if it wants to.
    pub fn from_record_stream<R: Read>(r: &mut R) -> Result<(ClientHello, Vec<u8>), TlsError> {
        let mut raw: Vec<u8> = Vec::new();
        let mut hs: Vec<u8> = Vec::new();
        let mut record_version: u16;
        loop {
            let mut hdr = [0u8; 5];
            read_exact(r, &mut hdr).map_err(|e| TlsError::Io(e.to_string()))?;
            if hdr[0] != 0x16 {
                return Err(TlsError::NotTlsRecord(hdr[0]));
            }
            record_version = u16::from_be_bytes([hdr[1], hdr[2]]);
            if record_version != 0x0303
                && record_version != 0x0301
                && record_version != 0x0302
                && record_version != 0x0300
                && record_version != 0x0304
            {
                return Err(TlsError::BadRecordVersion(record_version));
            }
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            if len > MAX_RECORD_LEN {
                return Err(TlsError::RecordTooLong(len));
            }
            let mut body = vec![0u8; len];
            read_exact(r, &mut body).map_err(|e| TlsError::Io(e.to_string()))?;
            raw.extend_from_slice(&hdr);
            raw.extend_from_slice(&body);
            if hs.is_empty() {
                if body.len() < 4 {
                    return Err(TlsError::ShortHandshake("handshake header"));
                }
                if body[0] != 0x01 {
                    return Err(TlsError::WrongHandshakeType(body[0]));
                }
                let total =
                    4 + ((body[1] as usize) << 16 | (body[2] as usize) << 8 | body[3] as usize);
                if body.len() >= total {
                    hs = body[..total].to_vec();
                    break;
                }
                hs = body;
            } else {
                hs.extend_from_slice(&body);
                let total = 4 + ((hs[1] as usize) << 16 | (hs[2] as usize) << 8 | hs[3] as usize);
                if hs.len() >= total {
                    break;
                }
            }
        }
        let mut ch = ClientHello::from_handshake_body(&hs)?;
        ch.record_version = record_version;
        Ok((ch, raw))
    }

    /// Parse a ClientHello from the bytes *after* the record headers, i.e.
    /// starting at the handshake type byte.
    pub fn from_handshake_body(b: &[u8]) -> Result<ClientHello, TlsError> {
        if b.len() < 4 {
            return Err(TlsError::ShortHandshake("handshake header"));
        }
        if b[0] != 0x01 {
            return Err(TlsError::WrongHandshakeType(b[0]));
        }
        let total = 4 + ((b[1] as usize) << 16 | (b[2] as usize) << 8 | b[3] as usize);
        let body = if b.len() >= total {
            &b[4..total]
        } else {
            &b[4..]
        };
        let mut p = ChReader::new(body);
        let legacy_version = p.u16().ok_or(TlsError::Truncated("legacy_version"))?;
        let rnd = p.fixed(32).ok_or(TlsError::Truncated("random"))?;
        let mut random = [0u8; 32];
        random.copy_from_slice(&rnd);
        let sid = p.u8_vec().ok_or(TlsError::Truncated("session_id"))?;
        let cs = p.u16_vec().ok_or(TlsError::Truncated("cipher_suites"))?;
        let comp = p
            .u8_vec()
            .ok_or(TlsError::Truncated("compression_methods"))?;
        let ext_blob = p.u16_vec_bytes().ok_or(TlsError::Truncated("extensions"))?;
        let mut extensions = Vec::new();
        let mut e = ChReader::new(&ext_blob);
        while let Some(id) = e.u16() {
            if let Some(data) = e.u16_vec_bytes() {
                extensions.push(Extension { id, data });
            } else {
                break;
            }
        }
        Ok(ClientHello {
            record_version: 0x0303,
            legacy_version,
            random,
            session_id: sid,
            cipher_suites: cs,
            compressions: comp,
            extensions,
            body_len: body.len(),
        })
    }

    pub fn ext_data(&self, id: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|x| x.id == id)
            .map(|x| x.data.as_slice())
    }

    pub fn supported_versions(&self) -> Vec<u16> {
        match self.ext_data(EXT_SUPPORTED_VERSIONS) {
            Some(d) => ChReader::new(d).u8_vec_u16().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn supported_groups(&self) -> Vec<u16> {
        match self.ext_data(EXT_SUPPORTED_GROUPS) {
            Some(d) => ChReader::new(d).u16_vec().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn key_share_groups(&self) -> Vec<u16> {
        match self.ext_data(EXT_KEY_SHARE) {
            Some(d) => {
                let mut out = Vec::new();
                let mut r = ChReader::new(d);
                if let Some(list) = r.u16_vec_bytes() {
                    let mut g = ChReader::new(&list);
                    while let Some(grp) = g.u16() {
                        out.push(grp);
                        if g.u16_vec_bytes().is_none() {
                            break;
                        }
                    }
                }
                out
            }
            None => Vec::new(),
        }
    }

    pub fn signature_algorithms(&self) -> Vec<u16> {
        match self.ext_data(EXT_SIGNATURE_ALGORITHMS) {
            Some(d) => ChReader::new(d).u16_vec().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn ec_point_formats(&self) -> Vec<u8> {
        match self.ext_data(EXT_EC_POINT_FORMATS) {
            Some(d) => ChReader::new(d).u8_vec().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn alpn(&self) -> Vec<String> {
        match self.ext_data(EXT_ALPN) {
            Some(d) => {
                let mut out = Vec::new();
                let mut r = ChReader::new(d);
                if let Some(list) = r.u16_vec_bytes() {
                    let mut p = ChReader::new(&list);
                    while let Some(s) = p.u8_vec() {
                        out.push(String::from_utf8_lossy(&s).into_owned());
                    }
                }
                out
            }
            None => Vec::new(),
        }
    }

    pub fn sni(&self) -> Option<String> {
        let d = self.ext_data(EXT_SERVER_NAME)?;
        let mut r = ChReader::new(d);
        let list = r.u16_vec_bytes()?;
        let mut p = ChReader::new(&list);
        let name_type = p.u8()?;
        if name_type != 0 {
            return None;
        }
        let name = p.u16_vec_bytes()?;
        Some(String::from_utf8_lossy(&name).into_owned())
    }

    pub fn psk_key_exchange_modes(&self) -> Vec<u8> {
        match self.ext_data(EXT_PSK_KEY_EXCHANGE_MODES) {
            Some(d) => ChReader::new(d).u8_vec().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Full wire bytes for this hello (record header included).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut hs: Vec<u8> = vec![0x01];
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for c in &self.cipher_suites {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(self.compressions.len() as u8);
        for c in &self.compressions {
            body.push(*c);
        }
        let mut exts: Vec<u8> = Vec::new();
        for x in &self.extensions {
            exts.extend_from_slice(&x.id.to_be_bytes());
            exts.extend_from_slice(&(x.data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&x.data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let n = body.len();
        hs.push((n >> 16) as u8);
        hs.push((n >> 8) as u8);
        hs.push(n as u8);
        hs.extend_from_slice(&body);
        let mut out: Vec<u8> = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        out.extend_from_slice(&hs);
        out
    }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                ))
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Minimal big-endian byte reader.
struct ChReader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> ChReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        ChReader { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.i + n > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u8_vec(&mut self) -> Option<Vec<u8>> {
        let n = self.u8()? as usize;
        Some(self.take(n)?.to_vec())
    }
    fn u16_vec(&mut self) -> Option<Vec<u16>> {
        let n = self.u16()? as usize;
        let bytes = self.take(n)?;
        let mut out = Vec::with_capacity(n / 2);
        let mut r = ChReader::new(bytes);
        while let Some(v) = r.u16() {
            out.push(v);
        }
        Some(out)
    }
    fn u8_vec_u16(&mut self) -> Option<Vec<u16>> {
        let n = self.u8()? as usize;
        let bytes = self.take(n)?;
        let mut out = Vec::with_capacity(n / 2);
        let mut r = ChReader::new(bytes);
        while let Some(v) = r.u16() {
            out.push(v);
        }
        Some(out)
    }
    fn u16_vec_bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u16()? as usize;
        Some(self.take(n)?.to_vec())
    }
    fn fixed(&mut self, n: usize) -> Option<Vec<u8>> {
        Some(self.take(n)?.to_vec())
    }
}

/// Human-readable names for the values that show up in a hello. Unknown ones
/// keep their numeric id so a report never hides something unexplained.
pub fn cipher_name(c: u16) -> String {
    const NAMES: &[(u16, &str)] = &[
        (0x1301, "TLS_AES_128_GCM_SHA256"),
        (0x1302, "TLS_AES_256_GCM_SHA384"),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        (0xcca8, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xcca9, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
        (0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        (0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
        (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
        (0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
        (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
        (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
        (0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
        (0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
        (0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
        (0x5600, "TLS_FALLBACK_SCSV"),
    ];
    for (v, n) in NAMES {
        if *v == c {
            return n.to_string();
        }
    }
    format!("unknown(0x{c:04x})")
}

pub fn extension_name(id: u16) -> &'static str {
    const NAMES: &[(u16, &str)] = &[
        (0, "server_name"),
        (10, "supported_groups"),
        (11, "ec_point_formats"),
        (13, "signature_algorithms"),
        (14, "use_alpn"),
        (15, "heartbeat"),
        (16, "application_layer_protocol_negotiation"),
        (17, "status_request"),
        (18, "signed_certificate_timestamp"),
        (21, "ech_outer_extensions"),
        (23, "session_ticket"),
        (27, "compressed_certificate"),
        (28, "signature_algorithms_cert"),
        (34, "encrypt_then_mac"),
        (35, "extended_master_secret"),
        (40, "extensions_old_format"),
        (43, "supported_groups"),
        (44, "point_formats"),
        (45, "psk_key_exchange_modes"),
        (47, "supported_versions"),
        (49, "pre_shared_key"),
        (50, "early_data"),
        (51, "key_share"),
        (53, "crrp"),
        (54, "post_handshake_auth"),
        (56, "signature_algorithms_cert"),
        (17513, "application_settings"),
        (65037, "encrypted_client_hello"),
        (65281, "renegotiation_info"),
    ];
    for (v, n) in NAMES {
        if *v == id {
            return n;
        }
    }
    "unknown"
}

pub fn group_name(g: u16) -> String {
    const NAMES: &[(u16, &str)] = &[
        (23, "secp256r1"),
        (24, "secp384r1"),
        (25, "secp521r1"),
        (29, "x25519"),
        (30, "x448"),
        (0x0020, "x25519mlkem768dilithium2"),
        (0x11ec, "mlkem768x25519"),
        (0xfe05, "ffdhe2048"),
        (0x0100, "curve25519 (legacy)"),
    ];
    for (v, n) in NAMES {
        if *v == g {
            return n.to_string();
        }
    }
    format!("unknown(0x{g:04x})")
}

pub fn version_name(v: u16) -> &'static str {
    match v {
        0x0002 => "SSLv2 hello type",
        0x0003 => "SSLv3 hello type",
        0x0300 => "SSLv3",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        0x7f16 => "TLS 1.3 draft-16",
        0x7f17 => "TLS 1.3 draft-17",
        0x7f18 => "TLS 1.3 draft-18",
        0x7f19 => "TLS 1.3 draft-19",
        0xff7f => "draft 0xff7f",
        _ => "unknown",
    }
}

/// Everything a report needs about one ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlsSummary {
    pub ja3: String,
    pub ja3_string: String,
    pub ja4: String,
    pub ja4_raw: String,
    pub wire_summary: String,
    pub grease_present: bool,
    pub record_version: u16,
    pub record_version_name: String,
    pub legacy_version: u16,
    pub legacy_version_name: String,
    pub highest_version: Option<u16>,
    pub highest_version_name: Option<String>,
    pub supported_versions: Vec<String>,
    pub ciphers: Vec<String>,
    pub cipher_ids: Vec<u16>,
    pub extensions: Vec<String>,
    pub extension_ids: Vec<u16>,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
    pub key_share_groups: Vec<String>,
    pub ec_point_formats: Vec<u8>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub compression_methods: Vec<u8>,
    pub session_id_len: usize,
    pub hello_len: usize,
    pub total_bytes: usize,
    pub ciphers_clean: usize,
    pub extensions_clean: usize,
}

impl TlsSummary {
    /// Do two observations describe the same hello? The identity fields are
    /// what a middlebox or server sees; byte counts are not part of it, since
    /// the reader may have seen a different number of record bytes.
    pub fn identity_matches(&self, other: &TlsSummary) -> bool {
        self.ja3 == other.ja3
            && self.ja4 == other.ja4
            && self.wire_summary == other.wire_summary
            && self.grease_present == other.grease_present
    }

    pub fn compute(ch: &ClientHello, total_bytes: usize) -> TlsSummary {
        let grease_present = ch
            .cipher_suites
            .iter()
            .chain(ch.extensions.iter().map(|e| &e.id))
            .chain(ch.supported_versions().iter())
            .chain(ch.supported_groups().iter())
            .chain(ch.signature_algorithms().iter())
            .chain(ch.key_share_groups().iter())
            .any(|v| is_grease(*v));

        let ciphers: Vec<u16> = ch
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        let ext_ids: Vec<u16> = ch
            .extensions
            .iter()
            .map(|e| e.id)
            .filter(|i| !is_grease(*i))
            .collect();
        let sigalgs: Vec<u16> = ch
            .signature_algorithms()
            .into_iter()
            .filter(|v| !is_grease(*v))
            .collect();
        let ecpf = ch.ec_point_formats();
        let versions: Vec<u16> = ch
            .supported_versions()
            .into_iter()
            .filter(|v| !is_grease(*v))
            .collect();

        // ---- JA3
        let ja3_string = format!(
            "{},{},{},{},{}",
            ch.legacy_version,
            ciphers
                .iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join(","),
            ext_ids
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(","),
            sigalgs
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(","),
            ecpf.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        let ja3 = md5_hex_str(&ja3_string);

        // ---- JA4
        let highest = if !versions.is_empty() {
            versions.iter().copied().max()
        } else if ch.legacy_version >= 0x0300 {
            Some(ch.legacy_version)
        } else {
            None
        };
        let version_tag = match highest {
            Some(0x0304) => "13",
            Some(0x0303) => "12",
            Some(0x0302) => "11",
            Some(0x0301) => "10",
            Some(0x0300) => "s3",
            Some(0x0002) => "s2",
            Some(_) => "00",
            None => "00",
        };
        let integrity = if grease_present { 'd' } else { 'i' };
        let alpn = ch.alpn();
        let alpn_tag = match alpn.first() {
            Some(a) => first_last(a),
            None => "00".to_string(),
        };
        let ja4_raw = format!(
            "t{version_tag}{integrity}{:02x}{:02x}{alpn_tag}",
            ciphers.len(),
            ext_ids
                .iter()
                .filter(|i| **i != EXT_SERVER_NAME && **i != EXT_ALPN)
                .count(),
        );
        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let cipher_str = sorted_ciphers
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join("-");
        let mut sorted_exts: Vec<u16> = ext_ids
            .iter()
            .copied()
            .filter(|i| *i != EXT_SERVER_NAME && *i != EXT_ALPN)
            .collect();
        sorted_exts.sort_unstable();
        let ext_str = format!(
            "{}{alpn_tag}",
            sorted_exts
                .iter()
                .map(|e| format!("{e:04x}"))
                .collect::<Vec<_>>()
                .join("-")
        );
        let sni = ch.sni();
        let sni_tag = match &sni {
            Some(s) => {
                let s = s.to_ascii_lowercase();
                if s.is_empty() {
                    "0000".to_string()
                } else {
                    s
                }
            }
            None => "0000".to_string(),
        };
        let ja4 = format!(
            "{ja4_raw}_{}_{}_{}",
            b32_trunc(&sha256(cipher_str.as_bytes()), 12),
            b32_trunc(&sha256(ext_str.as_bytes()), 12),
            sni_tag
        );

        // ---- hardvoy wire summary (ordering preserving, Akamai style)
        let wire_summary = format!(
            "hw1.{:02x}.{:02x}.{}|{}|{}",
            ciphers.len(),
            ext_ids.len(),
            ext_ids
                .iter()
                .map(|e| format!("{e:04x}"))
                .collect::<Vec<_>>()
                .join("."),
            ciphers
                .iter()
                .map(|c| format!("{c:04x}"))
                .collect::<Vec<_>>()
                .join("."),
            if alpn.is_empty() {
                "0000".to_string()
            } else {
                alpn.join(",")
            },
        );

        TlsSummary {
            ja3,
            ja3_string,
            ja4,
            ja4_raw,
            wire_summary,
            grease_present,
            record_version: ch.record_version,
            record_version_name: version_name(ch.record_version).to_string(),
            legacy_version: ch.legacy_version,
            legacy_version_name: version_name(ch.legacy_version).to_string(),
            highest_version: highest,
            highest_version_name: highest.map(|v| version_name(v).to_string()),
            supported_versions: versions
                .iter()
                .map(|v| version_name(*v).to_string())
                .collect(),
            ciphers: ciphers.iter().map(|c| cipher_name(*c)).collect(),
            cipher_ids: ciphers,
            extensions: ext_ids
                .iter()
                .map(|e| format!("{e}({})", extension_name(*e)))
                .collect(),
            extension_ids: ext_ids,
            signature_algorithms: sigalgs.iter().map(|s| sigalg_name(*s)).collect(),
            supported_groups: ch
                .supported_groups()
                .into_iter()
                .filter(|g| !is_grease(*g))
                .map(group_name)
                .collect(),
            key_share_groups: ch
                .key_share_groups()
                .into_iter()
                .filter(|g| !is_grease(*g))
                .map(group_name)
                .collect(),
            ec_point_formats: ecpf,
            psk_key_exchange_modes: ch.psk_key_exchange_modes(),
            alpn,
            sni,
            compression_methods: ch.compressions.clone(),
            session_id_len: ch.session_id.len(),
            hello_len: ch.body_len,
            total_bytes,
            ciphers_clean: ch.cipher_suites.len(),
            extensions_clean: ch.extensions.len(),
        }
    }
}

pub fn sigalg_name(s: u16) -> String {
    const NAMES: &[(u16, &str)] = &[
        (0x0401, "rsa_pkcs1_sha256"),
        (0x0501, "rsa_pkcs1_sha384"),
        (0x0601, "rsa_pkcs1_sha512"),
        (0x0403, "ecdsa_secp256r1_sha256"),
        (0x0503, "ecdsa_secp384r1_sha384"),
        (0x0603, "ecdsa_secp521r1_sha512"),
        (0x0804, "rsa_pss_pss_sha256"),
        (0x0805, "rsa_pss_pss_sha384"),
        (0x0806, "rsa_pss_pss_sha512"),
        (0x0807, "ed25519"),
        (0x0808, "ed448"),
        (0x0201, "rsa_pkcs1_sha1"),
        (0x0203, "ecdsa_sha1"),
        (0x081a, "ml-dsa-65 (draft)"),
    ];
    for (v, n) in NAMES {
        if *v == s {
            return n.to_string();
        }
    }
    format!("unknown(0x{s:04x})")
}

// ---------------------------------------------------------------------------
// building our own hello

/// An explicit ClientHello specification. hardvoy uses this to measure the
/// fingerprint it produces itself and to prove an egress path does not alter
/// the hello on the way out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloSpec {
    pub name: String,
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn: Vec<String>,
    /// Extension ids in the order they should be written.
    pub extension_order: Vec<u16>,
    pub session_id: Vec<u8>,
    pub compressions: Vec<u8>,
    pub sni: Option<String>,
    pub grease: bool,
}

impl HelloSpec {
    /// The hello hardvoy calls `stock`: a plain TLS 1.3-capable client with no
    /// GREASE, ALPN h2, x25519, and the common RSA/ECDSA/ChaCha suites.
    pub fn stock() -> HelloSpec {
        HelloSpec {
            name: "stock".into(),
            legacy_version: 0x0303,
            ciphers: vec![
                0x1301, 0x1303, 0x1302, 0xc02f, 0xc030, 0xcca8, 0xcca9, 0xc02b, 0xc02c, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x00ff,
            ],
            supported_versions: vec![0x0304, 0x0303],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019],
            key_share_groups: vec![0x001d],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0603, 0x0601,
            ],
            ec_point_formats: vec![0],
            alpn: vec!["h2".into(), "http/1.1".into()],
            extension_order: vec![0, 16, 51, 10, 43, 13, 45, 47, 11, 5, 35, 23, 18, 17, 16],
            session_id: vec![0u8; 32],
            compressions: vec![0],
            sni: Some("hardvoy.invalid".into()),
            grease: false,
        }
    }

    /// Same suites, but GREASE everywhere: proves the fingerprinters follow
    /// RFC 8701 and that a browser which randomises code points still gives a
    /// stable JA3/JA4.
    pub fn greased(mut self) -> HelloSpec {
        self.name = format!("{}-greased", self.name);
        self.grease = true;
        self
    }

    pub fn to_hello(&self) -> ClientHello {
        let mut exts: Vec<Extension> = Vec::new();
        let mut seen: Vec<u16> = Vec::new();
        // `0x1a1a` etc. GREASE code points, one per extension slot when asked.
        let grease_sv: u16 = 0x1a1a;
        for (i, id) in self.extension_order.iter().enumerate() {
            if seen.contains(id) {
                continue;
            }
            seen.push(*id);
            if self.grease && i % 3 == 0 {
                exts.push(Extension {
                    id: grease_code(i as u16),
                    data: Vec::new(),
                });
            }
            let data: Vec<u8> = match *id {
                EXT_SERVER_NAME => match &self.sni {
                    Some(s) => {
                        let mut d: Vec<u8> = Vec::new();
                        let mut inner: Vec<u8> = vec![0x00];
                        inner.extend_from_slice(&(s.len() as u16).to_be_bytes());
                        inner.extend_from_slice(s.as_bytes());
                        d.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                        d.extend_from_slice(&inner);
                        d
                    }
                    None => Vec::new(),
                },
                EXT_ALPN => {
                    let mut inner: Vec<u8> = Vec::new();
                    for p in &self.alpn {
                        inner.push(p.len() as u8);
                        inner.extend_from_slice(p.as_bytes());
                    }
                    let mut d: Vec<u8> = Vec::new();
                    d.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                    d.extend_from_slice(&inner);
                    d
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut v: Vec<u8> = Vec::new();
                    for ver in &self.supported_versions {
                        v.extend_from_slice(&ver.to_be_bytes());
                    }
                    let mut d = vec![v.len() as u8];
                    if self.grease {
                        d = vec![(v.len() + 2) as u8];
                        d.extend_from_slice(&grease_sv.to_be_bytes());
                    }
                    d.extend_from_slice(&v);
                    d
                }
                EXT_SUPPORTED_GROUPS => {
                    let mut v: Vec<u8> = Vec::new();
                    for g in &self.supported_groups {
                        v.extend_from_slice(&g.to_be_bytes());
                    }
                    let mut d = Vec::new();
                    d.extend_from_slice(&(v.len() as u16).to_be_bytes());
                    d.extend_from_slice(&v);
                    d
                }
                EXT_KEY_SHARE => {
                    let mut v: Vec<u8> = Vec::new();
                    for g in &self.key_share_groups {
                        let key = vec![0xabu8; 32];
                        v.extend_from_slice(&g.to_be_bytes());
                        v.extend_from_slice(&(key.len() as u16).to_be_bytes());
                        v.extend_from_slice(&key);
                    }
                    let mut d = Vec::new();
                    d.extend_from_slice(&(v.len() as u16).to_be_bytes());
                    d.extend_from_slice(&v);
                    d
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    let mut v: Vec<u8> = Vec::new();
                    for s in &self.signature_algorithms {
                        v.extend_from_slice(&s.to_be_bytes());
                    }
                    let mut d = Vec::new();
                    d.extend_from_slice(&(v.len() as u16).to_be_bytes());
                    d.extend_from_slice(&v);
                    d
                }
                EXT_EC_POINT_FORMATS => {
                    let mut d = vec![self.ec_point_formats.len() as u8];
                    d.extend_from_slice(&self.ec_point_formats);
                    d
                }
                EXT_PSK_KEY_EXCHANGE_MODES => vec![0x01, 0x01],
                5 => vec![0x01, 0x00, 0x00, 0x00, 0x00], // status_request
                35 => Vec::new(),                        // extended_master_secret
                23 => Vec::new(),                        // session_ticket
                18 => Vec::new(),                        // SCT
                17 => Vec::new(),                        // status_request_v2
                other => {
                    let _ = other;
                    Vec::new()
                }
            };
            exts.push(Extension { id: *id, data });
        }
        let mut cs = self.ciphers.clone();
        if self.grease {
            cs.insert(0, 0x1a1a);
            cs.push(0x0a0a);
        }
        let mut comp = self.compressions.clone();
        if self.grease {
            comp.insert(0, 0x1a);
        }
        ClientHello {
            record_version: 0x0303,
            legacy_version: self.legacy_version,
            random: [0x42u8; 32],
            session_id: self.session_id.clone(),
            cipher_suites: cs,
            compressions: comp,
            extensions: exts,
            body_len: 0,
        }
    }
}

/// The bytes a TLS sniffer sends back before hanging up: a TLS alert so the
/// connecting client gets an explicit failure instead of a silent reset.
pub const ALERT_CLOSE_NOTIFY: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
pub const ALERT_HANDSHAKE_FAILURE: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];

pub fn hex_dump(b: &[u8]) -> String {
    hex(b)
}

/// RFC 8701 GREASE code point for index `n` in 0..16.
pub fn grease_code(n: u16) -> u16 {
    (n << 12) | 0x0a00 | (n << 4) | 0x0a
}

pub fn from_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientHello {
        ClientHello {
            record_version: 0x0303,
            legacy_version: 0x0303,
            random: [7u8; 32],
            session_id: vec![0u8; 32],
            cipher_suites: vec![0x1301, 0x1303, 0x1302, 0xc02f],
            compressions: vec![0],
            extensions: vec![
                Extension {
                    id: 0,
                    data: vec![],
                },
                Extension {
                    id: 16,
                    data: vec![],
                },
                Extension {
                    id: 51,
                    data: vec![],
                },
                Extension {
                    id: 10,
                    data: vec![],
                },
                Extension {
                    id: 11,
                    data: vec![1, 0],
                },
                Extension {
                    id: 13,
                    data: vec![0x00, 0x02, 0x04, 0x03],
                },
                Extension {
                    id: 47,
                    data: vec![2, 0x03, 0x04],
                },
            ],
            body_len: 0,
        }
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xdada));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0017));
        assert!(!is_grease(0xa0a0));
        assert!(!is_grease(0x1aab));
    }

    #[test]
    fn roundtrip_build_parse() {
        let spec = HelloSpec::stock();
        let hello = spec.to_hello();
        let bytes = hello.to_bytes();
        let (back, raw) = ClientHello::from_record_stream(&mut &bytes[..]).expect("parse");
        assert_eq!(raw.len(), bytes.len());
        assert_eq!(back.cipher_suites, spec.ciphers);
        assert_eq!(back.supported_versions(), vec![0x0304, 0x0303]);
        assert_eq!(back.supported_groups().len(), 4);
        assert_eq!(back.key_share_groups(), vec![0x001d]);
        assert_eq!(back.sni().as_deref(), Some("hardvoy.invalid"));
        assert_eq!(back.alpn(), vec!["h2".to_string(), "http/1.1".to_string()]);
        let uniq: Vec<u16> = {
            let mut u: Vec<u16> = Vec::new();
            for i in &spec.extension_order {
                if !u.contains(i) {
                    u.push(*i);
                }
            }
            u
        };
        assert_eq!(back.extension_ids_len(), uniq.len());
        assert_eq!(back.ec_point_formats(), vec![0]);
    }

    #[test]
    fn greased_hello_still_has_clean_fingerprints() {
        let plain = HelloSpec::stock().to_hello();
        let greased = HelloSpec::stock().greased().to_hello();
        let a = TlsSummary::compute(&plain, 0);
        let b = TlsSummary::compute(&greased, 0);
        assert!(b.grease_present);
        assert!(!a.grease_present);
        // GREASE must not change JA3 at all, and must not change the JA4 hash
        // sections; only the integrity-mode character is allowed to differ.
        assert_eq!(a.ja3, b.ja3, "JA3 changed when GREASE was added");
        let aj: Vec<&str> = a.ja4.split('_').collect();
        let bj: Vec<&str> = b.ja4.split('_').collect();
        assert_eq!(&aj[1..], &bj[1..], "JA4 hash sections changed with GREASE");
        assert!(aj[0].starts_with("t13i"), "plain: {}", aj[0]);
        assert!(bj[0].starts_with("t13d"), "greased: {}", bj[0]);
    }

    #[test]
    fn ja3_format_matches_definition() {
        let s = TlsSummary::compute(&sample(), 100);
        assert_eq!(
            s.ja3_string,
            "771,1301,1303,1302,c02f,0,16,51,10,11,13,47,1027,0"
        );
        assert_eq!(s.ja3.len(), 32);
    }

    #[test]
    fn ja4_fields_are_right() {
        let s = TlsSummary::compute(&sample(), 100);
        // t = TLS over TCP, 13 = highest supported version, i = no GREASE,
        // 04 ciphers, 05 extensions (SNI and ALPN excluded), h1 from ALPN h2.
        assert!(s.ja4_raw.starts_with("t13i"), "got {}", s.ja4_raw);
        assert!(s.ja4_raw.contains("0405"), "got {}", s.ja4_raw);
        let parts: Vec<&str> = s.ja4.split('_').collect();
        assert_eq!(parts.len(), 4, "ja4 = {}", s.ja4);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        // no SNI data in this sample -> 0000
        assert_eq!(parts[3], "0000");
    }

    #[test]
    fn sni_appears_in_ja4() {
        let mut ch = sample();
        let host = "example.invalid";
        let mut inner: Vec<u8> = vec![0x00];
        inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
        inner.extend_from_slice(host.as_bytes());
        let mut d: Vec<u8> = Vec::new();
        d.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        d.extend_from_slice(&inner);
        ch.extensions.iter_mut().find(|e| e.id == 0).unwrap().data = d;
        let s = TlsSummary::compute(&ch, 0);
        assert!(s.ja4.ends_with("_example.invalid"));
        assert_eq!(s.sni.as_deref(), Some("example.invalid"));
    }

    #[test]
    fn record_stream_reassembles_multi_record_hello() {
        let bytes = HelloSpec::stock().to_hello().to_bytes();
        // split into chunks to force the multi-read path
        let mut cur = &bytes[..];
        let (back, raw) = {
            let mut reader = ChunkedReader::new(&mut cur, 7);
            ClientHello::from_record_stream(&mut reader).expect("reassemble")
        };
        assert_eq!(raw.len(), bytes.len());
        assert_eq!(back.supported_versions(), vec![0x0304, 0x0303]);
    }

    #[test]
    fn rejects_plaintext_as_not_tls() {
        let mut cur = &b"GET / HTTP/1.1\r\n\r\n"[..];
        let e = ClientHello::from_record_stream(&mut cur).unwrap_err();
        assert!(matches!(e, TlsError::NotTlsRecord(b'G')));
    }

    #[test]
    fn truncates_cleanly_on_short_input() {
        let bytes = HelloSpec::stock().to_hello().to_bytes();
        let short = &bytes[..20];
        let e = ClientHello::from_record_stream(&mut &short[..]).unwrap_err();
        assert!(matches!(e, TlsError::Io(_)), "got {e:?}");
    }

    struct ChunkedReader<'a> {
        src: &'a mut &'a [u8],
        n: usize,
    }
    impl<'a> ChunkedReader<'a> {
        fn new(src: &'a mut &'a [u8], n: usize) -> Self {
            ChunkedReader { src, n }
        }
    }
    impl<'a> Read for ChunkedReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let k = self.n.min(buf.len()).min(self.src.len());
            buf[..k].copy_from_slice(&self.src[..k]);
            *self.src = &self.src[k..];
            Ok(k)
        }
    }

    impl ClientHello {
        fn extension_ids_len(&self) -> usize {
            self.extensions.len()
        }
    }
}
