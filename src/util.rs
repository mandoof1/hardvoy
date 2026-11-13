//! Small helpers: hashing, encodings, time formatting, canonical JSON.
//!
//! hardvoy deliberately avoids a date/library crate: the RFC 3339 formatter
//! below is a plain days-from-civil conversion and is unit tested.

use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Lowercase hex of arbitrary bytes.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

pub fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest as MdDigest, Md5};
    let mut h = Md5::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// SHA-256 of a UTF-8 string.
pub fn sha256_hex_str(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

pub fn md5_hex_str(s: &str) -> String {
    md5_hex(s.as_bytes())
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

const B32_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding. JA4 truncates the result to 12
/// characters, which is what `b32_trunc` is for.
pub fn b32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for b in bytes {
        acc = (acc << 8) | (*b as u32);
        nbits += 8;
        while nbits >= 5 {
            let take = (acc >> (nbits - 5)) & 0x1f;
            out.push(B32_ALPHA[take as usize] as char);
            nbits -= 5;
        }
        if nbits > 0 {
            // keep remaining low bits for the next byte
            acc &= (1u32 << nbits) - 1;
        }
    }
    if nbits > 0 {
        let take = (acc << (5 - nbits)) & 0x1f;
        out.push(B32_ALPHA[take as usize] as char);
    }
    out
}

pub fn b32_trunc(bytes: &[u8], n: usize) -> String {
    let s = b32(bytes);
    s.chars().take(n).collect()
}

/// First and last character of a protocol id, e.g. `h2` -> `h2`,
/// `http/1.1` -> `h1`. Empty -> `00`.
pub fn first_last(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    match chars.len() {
        0 => "00".to_string(),
        1 => format!("{c}{c}", c = chars[0]),
        _ => format!("{}{}", chars[0], chars[chars.len() - 1]),
    }
}

/// Truncate to `n` characters (char-safe) and replace anything that is not
/// `[a-z0-9._-]` with `_`, so fingerprints stay printable/quotable.
pub fn sanitize(s: &str, n: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.len() > n {
        out.truncate(n);
    }
    out
}

// ---------------------------------------------------------------------------
// time

/// Milliseconds since the Unix epoch.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    now_millis() / 1000
}

/// Split a Unix day number into (year, month, day) using Howard Hinnant's
/// days_from_civil inverse.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `1970-01-01T00:00:00Z` style UTC timestamp from milliseconds.
pub fn rfc3339_utc(millis: u64) -> String {
    let secs = (millis / 1000) as i64;
    let day = secs.div_euclid(86_400);
    let soc = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(day);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        soc / 3600,
        (soc % 3600) / 60,
        soc % 60
    )
}

// ---------------------------------------------------------------------------
// canonical JSON

/// Turn any serde value into a `serde_json::Value` whose map keys are sorted
/// (serde_json's default map is a BTreeMap, so `to_string` is already
/// canonical) and whose floats are rendered with a fixed amount of precision.
///
/// Fixed precision matters: canvas/audio hashes must not flip because a
/// sub-nanosecond timing difference changed the 15th significant digit.
pub fn canonical_json(v: &serde_json::Value) -> String {
    let norm = normalize(v);
    serde_json::to_string(&norm).unwrap_or_else(|_| "null".to_string())
}

fn normalize(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value as V;
    match v {
        V::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                out.insert(k.clone(), normalize(&map[k]));
            }
            V::Object(out)
        }
        V::Array(items) => V::Array(items.iter().map(normalize).collect()),
        V::Number(n) => {
            if let Some(f) = n.as_f64() {
                if n.is_f64() {
                    // 6 decimal places is far more precision than any browser
                    // API we read is stable to, and it makes repeat runs
                    // reproducible.
                    return V::String(format!("{:.6}", f));
                }
            }
            V::Number(n.clone())
        }
        other => other.clone(),
    }
}

/// Stable 64-bit fingerprint of a canonical JSON blob, as 16 hex chars. Used
/// where a short id is nicer than a full SHA-256 (table columns).
pub fn short_hash(s: &str) -> String {
    let d = sha256(s.as_bytes());
    hex(&d[..8])
}

/// Deterministic pseudo-random id from a seed, used for run labels.
/// Ask the kernel for a free loopback TCP port, then release it.
pub fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    drop(l);
    Ok(port)
}

pub fn tag(prefix: &str, seed: u64) -> String {
    format!("{prefix}-{}", short_hash(&seed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex_str("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex_str("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn base32_known_vectors() {
        // RFC 4648 test vectors, lowercase, unpadded.
        assert_eq!(b32(b""), "");
        assert_eq!(b32(b"f"), "my");
        assert_eq!(b32(b"fo"), "mzxq");
        assert_eq!(b32(b"foo"), "mzxw6");
        assert_eq!(b32(b"foob"), "mzxw6yq");
        assert_eq!(b32(b"fooba"), "mzxw6ytb");
        assert_eq!(b32(b"foobar"), "mzxw6ytboi");
        assert_eq!(b32_trunc(b"foobar", 12), "mzxw6ytboi".to_string());
    }

    #[test]
    fn rfc3339_vectors() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_741_996_800_000), "2025-03-15T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000_000), "2001-09-09T01:46:40Z");
        // pre-epoch dates should not panic (not normally needed)
        assert_eq!(rfc3339_utc(1), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn first_last_vector() {
        assert_eq!(first_last("h2"), "h2");
        assert_eq!(first_last("http/1.1"), "h1");
        assert_eq!(first_last(""), "00");
        assert_eq!(first_last("q"), "qq");
    }

    #[test]
    fn canonical_json_sorts_keys_and_fixes_floats() {
        let a = serde_json::json!({"b": 1, "a": 1.0000004, "c": [2, {"y": 1, "x": 2}]});
        let b = serde_json::json!({"c": [2, {"x": 2, "y": 1}], "a": 1.0000002, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            canonical_json(&a),
            r#"{"a":"1.000000","b":1,"c":[2,{"x":2,"y":1}]}"#
        );
    }

    #[test]
    fn sanitize_keeps_printable() {
        assert_eq!(sanitize("example.com", 16), "example.com");
        let s = sanitize("ExAmple COM:8080", 16);
        assert_eq!(s.chars().count(), 16);
        assert!(!s
            .chars()
            .any(|c| c.is_ascii_uppercase() || c == ' ' || c == ':'));
        assert_eq!(sanitize("héllo", 8), "h_llo");
    }

    #[test]
    fn short_hash_is_stable() {
        assert_eq!(short_hash("abc"), short_hash("abc"));
        assert_ne!(short_hash("abc"), short_hash("abd"));
        assert_eq!(short_hash("abc").len(), 16);
    }
}
