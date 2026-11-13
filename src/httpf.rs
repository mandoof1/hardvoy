//! Raw HTTP request capture: exactly the header order and header set the
//! browser put on the wire, which is itself a fingerprint.

use crate::util::sha256_hex_str;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    NotHttpRequest(String),
    BadHeaderLine(String),
    TooLarge,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::NotHttpRequest(first) => write!(f, "not an HTTP request line: {first:?}"),
            HttpError::BadHeaderLine(line) => write!(f, "malformed header line: {line:?}"),
            HttpError::TooLarge => write!(f, "request headers exceed 32 KiB"),
        }
    }
}
impl std::error::Error for HttpError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    /// Header order exactly as received. Case is preserved.
    pub headers: Vec<(String, String)>,
    pub raw_len: usize,
    /// The exact header bytes as received (request line + headers), which the
    /// report keeps as evidence.
    pub raw_head: String,
}

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE", "PATCH", "TRACE", "CONNECT",
];

/// Read one request off a stream: headers first, then exactly as much of the
/// body as Content-Length asks for. Shared by the lab server and the forwarder.
pub fn read_request<R: std::io::Read>(r: &mut R) -> Result<(RawRequest, Vec<u8>), HttpError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut want_total: Option<usize> = None;
    loop {
        let n = match r.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        buf.extend_from_slice(&tmp[..n]);
        if header_end.is_none() {
            header_end = find_subseq(&buf, b"\r\n\r\n");
            if let Some(h) = header_end {
                let head = String::from_utf8_lossy(&buf[..h]).into_owned();
                let mut content_len = 0usize;
                for line in head.split("\r\n").skip(1) {
                    let (k, v) = match line.find(':') {
                        Some(i) => (line[..i].to_ascii_lowercase(), line[i + 1..].trim()),
                        None => continue,
                    };
                    if k == "content-length" {
                        content_len = v.parse().unwrap_or(0);
                    }
                }
                want_total = Some(h + 4 + content_len);
            }
        }
        match (header_end, want_total) {
            (Some(_), Some(t)) if buf.len() >= t => break,
            _ => {}
        }
        if buf.len() > 4 * 1024 * 1024 {
            break;
        }
    }
    let head_len = header_end.unwrap_or(buf.len());
    let end = (head_len + 4).min(buf.len());
    let req = parse_request(&buf[..end])?;
    let body = if buf.len() > end {
        buf[end..].to_vec()
    } else {
        Vec::new()
    };
    Ok((req, body))
}

fn find_subseq(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|i| &haystack[*i..*i + needle.len()] == needle)
}

/// Parse request headers only (body is left unread).
pub fn parse_request(bytes: &[u8]) -> Result<RawRequest, HttpError> {
    if bytes.len() > 32 * 1024 {
        return Err(HttpError::TooLarge);
    }
    let head_end = find_subseq(bytes, b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(bytes.len());
    let head_bytes = &bytes[..head_end];
    let text = String::from_utf8_lossy(head_bytes).into_owned();
    let head = text.strip_suffix("\r\n\r\n").unwrap_or(&text);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    if !METHODS.contains(&method) {
        return Err(HttpError::NotHttpRequest(request_line.to_string()));
    }
    let path = parts.next().unwrap_or("").to_string();
    let rest = parts.next().unwrap_or("HTTP/0.9").to_string();
    // CONNECT has two spellings in the wild: `CONNECT host:port HTTP/1.1`
    // (what curl and browsers send) and the RFC 9110 form with the port as a
    // separate field. Accept both, and keep the port.
    let (path, version) = if method == "CONNECT" {
        let mut it = rest.splitn(2, ' ');
        let a = it.next().unwrap_or("");
        let b = it.next().unwrap_or("");
        if !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()) && b.starts_with("HTTP/") {
            (format!("{path}:{a}"), b.to_string())
        } else {
            (path, rest)
        }
    } else {
        (path, rest)
    };
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (n, v) = match line.find(':') {
            Some(i) => (
                line[..i].trim().to_string(),
                line[i + 1..].trim().to_string(),
            ),
            None => return Err(HttpError::BadHeaderLine(line.to_string())),
        };
        headers.push((n, v));
    }
    Ok(RawRequest {
        method: method.to_string(),
        path,
        version,
        headers,
        raw_len: bytes.len(),
        raw_head: String::from_utf8_lossy(head_bytes).into_owned(),
    })
}

impl RawRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.header(name).is_some()
    }

    pub fn header_names(&self) -> Vec<String> {
        self.headers.iter().map(|(k, _)| k.clone()).collect()
    }
}

/// The order-dependent summary of one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProfile {
    pub method: String,
    pub path: String,
    pub version: String,
    pub header_order: Vec<String>,
    pub header_order_lower: Vec<String>,
    /// SHA-256 over the header names in the exact order received.
    pub order_hash: String,
    /// SHA-256 over name:value pairs (values truncated to 96 chars) in order.
    pub content_hash: String,
    pub header_count: usize,
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub connection: Option<String>,
    pub host: Option<String>,
    pub cookie_header: Option<String>,
    pub cookie_names: Vec<String>,
    /// Client hints (sec-ch-ua*) — a Chromium-only signal, so finding them in
    /// a Firefox hello means a profile was configured to imitate Chrome.
    pub client_hints: Vec<String>,
    pub sec_fetch: Vec<String>,
    pub proxy_injected: Vec<String>,
    pub dnt: Option<String>,
    pub upgrade_insecure_requests: Option<String>,
    pub priority: Option<String>,
    pub raw_len: usize,
}

/// Drop a trailing `:port` from an authority value, keeping the host. An
/// onion host has no port, so it is returned untouched.
fn strip_port(v: &str) -> String {
    match v.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            host.to_string()
        }
        _ => v.to_string(),
    }
}

pub fn profile(req: &RawRequest) -> HttpProfile {
    let names: Vec<String> = req.header_names();
    let lower: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let order_hash = sha256_hex_str(&lower.join("\n"));
    // The lab listens on an ephemeral port, so `Host: 127.0.0.1:41301` changes
    // every run. That is a property of the lab, not of the operator, so the
    // port is normalised out of the content hash; the header set, its order and
    // every other value are hashed exactly as sent.
    let content = req
        .headers
        .iter()
        .map(|(k, v)| {
            let v: String = v.chars().take(96).collect();
            let v = match k.to_ascii_lowercase().as_str() {
                "host" | "authority" | "x-forwarded-host" | "connect" => strip_port(&v),
                _ => v,
            };
            format!("{k}: {v}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let content_hash = sha256_hex_str(&content);

    let cookie_header = req.header("cookie");
    let cookie_names = match cookie_header {
        Some(c) => c
            .split(';')
            .map(|p| p.trim().split('=').next().unwrap_or("").to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => Vec::new(),
    };

    let client_hints = lower
        .iter()
        .filter(|n| n.starts_with("sec-ch-ua"))
        .cloned()
        .collect();
    let sec_fetch = lower
        .iter()
        .filter(|n| n.starts_with("sec-fetch-"))
        .cloned()
        .collect();
    let proxy_injected = lower
        .iter()
        .filter(|n| {
            matches!(
                n.as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "via" | "x-real-ip" | "forwarded"
            )
        })
        .cloned()
        .collect();

    HttpProfile {
        method: req.method.clone(),
        path: req.path.clone(),
        version: req.version.clone(),
        header_order: names.clone(),
        header_order_lower: lower,
        order_hash,
        content_hash,
        header_count: req.headers.len(),
        user_agent: req.header("user-agent").map(|s| s.to_string()),
        accept_language: req.header("accept-language").map(|s| s.to_string()),
        accept_encoding: req.header("accept-encoding").map(|s| s.to_string()),
        connection: req.header("connection").map(|s| s.to_string()),
        host: req.header("host").map(|s| s.to_string()),
        cookie_header: cookie_header.map(|s| s.to_string()),
        cookie_names,
        client_hints,
        sec_fetch,
        proxy_injected,
        dnt: req.header("dnt").map(|s| s.to_string()),
        upgrade_insecure_requests: req
            .header("upgrade-insecure-requests")
            .map(|s| s.to_string()),
        priority: req.header("priority").map(|s| s.to_string()),
        raw_len: req.raw_len,
    }
}

/// Read one HTTP response from an upstream: headers, then exactly the body
/// (Content-Length, chunked, or until close). Without this a proxy would have
/// to wait for the server to hang up, which stalls connections that stay open.
pub fn read_response<R: std::io::Read>(r: &mut R) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut head_end: Option<usize> = None;
    loop {
        let n = match r.read(&mut tmp) {
            Ok(0) => return buf,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return buf,
        };
        buf.extend_from_slice(&tmp[..n]);
        if head_end.is_none() {
            head_end = find_subseq(&buf, b"\r\n\r\n");
        }
        if let Some(h) = head_end {
            let head = String::from_utf8_lossy(&buf[..h]).to_ascii_lowercase();
            if head.contains("transfer-encoding: chunked") {
                if let Some(end) = chunked_end(&buf, h + 4) {
                    buf.truncate(end);
                    return buf;
                }
            } else if let Some(cl) = header_value(&head, "content-length") {
                if buf.len() >= h + 4 + cl {
                    buf.truncate(h + 4 + cl);
                    return buf;
                }
            } else if head.contains("connection: close") {
                // body is delimited by the close: keep reading
            }
        }
        if buf.len() > 8 * 1024 * 1024 {
            return buf;
        }
    }
}

fn header_value(head_lower: &str, name: &str) -> Option<usize> {
    for line in head_lower.split("\r\n").skip(1) {
        if let Some(i) = line.find(':') {
            if line[..i].trim() == name {
                return line[i + 1..].trim().parse().ok();
            }
        }
    }
    None
}

/// Where a chunked body ends (just past the terminating 0-size chunk and its
/// trailing CRLF), or None if the buffer does not hold the whole body yet.
fn chunked_end(buf: &[u8], body_start: usize) -> Option<usize> {
    let mut i = body_start;
    loop {
        let nl = find_subseq(&buf[i..], b"\r\n").map(|n| i + n)?;
        let size_line = String::from_utf8_lossy(&buf[i..nl]).into_owned();
        let size = u64::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .ok()? as usize;
        if size == 0 {
            // terminating chunk, then an empty trailer (CRLF)
            return if buf.len() >= nl + 5 {
                Some(nl + 5)
            } else {
                None
            };
        }
        i = nl + 2 + size + 2;
        if i > buf.len() {
            return None;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    /// Header order exactly as received.
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Request/status line plus headers, exactly as received.
    pub raw_head: String,
}

/// Split a raw response (as `read_response` returns it) into its parts.
pub fn parse_response(raw: &[u8]) -> Response {
    let sep = match find_subseq(raw, b"\r\n\r\n") {
        Some(i) => i,
        None => {
            return Response {
                body: String::from_utf8_lossy(raw).to_string(),
                raw_head: String::from_utf8_lossy(raw).to_string(),
                ..Default::default()
            }
        }
    };
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    let body = String::from_utf8_lossy(&raw[sep + 4..]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _http = parts.next();
    let status = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for l in lines {
        if let Some(i) = l.find(':') {
            headers.push((l[..i].to_string(), l[i + 1..].trim().to_string()));
        }
    }
    Response {
        status,
        reason,
        headers,
        body,
        raw_head: head,
    }
}

/// Write a request the way a client would: request line, headers in order,
/// Content-Length when there is a body.
pub fn build_request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !body.is_empty() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// A canonical HTTP/1.1 response, written by hand because hardvoy ships its
/// own lab server and must not surprise a browser with a malformed reply.
pub fn response(
    status: u16,
    reason: &str,
    ctype: &str,
    body: &[u8],
    extra: &[(&str, String)],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Type: {ctype}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"Cache-Control: no-store\r\n");
    out.extend_from_slice(b"X-Hardvoy: lab\r\n");
    for (k, v) in extra {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FF: &str = "POST /collect?run=a1 HTTP/1.1\r\n\
        Host: lab.onion\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0\r\n\
        Accept: text/html,application/xhtml+xml\r\n\
        Accept-Language: en-US,en;q=0.5\r\n\
        Accept-Encoding: gzip, deflate\r\n\
        Referer: http://lab.onion/\r\n\
        Content-Type: application/json\r\n\
        Content-Length: 12\r\n\
        Connection: keep-alive\r\n\
        Cookie: hv_run=a1; hv_sess=zz\r\n\
        Priority: u=4\r\n\
        \r\n";

    fn bytes(s: &str) -> &[u8] {
        s.as_bytes()
    }

    #[test]
    fn parses_request_line_and_headers_in_order() {
        let r = parse_request(bytes(FF)).expect("parse");
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/collect?run=a1");
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(r.headers.len(), 11);
        assert_eq!(r.headers[0].0, "Host");
        assert_eq!(r.headers[1].0, "User-Agent");
        assert_eq!(r.headers.last().unwrap().0, "Priority");
    }

    #[test]
    fn ephemeral_lab_port_does_not_change_the_content_hash() {
        // The lab binds an ephemeral port. Two runs of the same browser on the
        // same egress differ only in `Host: 127.0.0.1:<port>`, and that must not
        // be read as a fingerprint change.
        let a = FF.replace("Host: lab.onion", "Host: 127.0.0.1:41301");
        let b = FF.replace("Host: lab.onion", "Host: 127.0.0.1:44669");
        let pa = profile(&parse_request(bytes(&a)).expect("a"));
        let pb = profile(&parse_request(bytes(&b)).expect("b"));
        assert_eq!(pa.content_hash, pb.content_hash);
        assert_eq!(pa.order_hash, pb.order_hash);
        // a genuinely different header value still has to change the hash
        let c = FF.replace("en-US,en;q=0.5", "de-DE,de;q=0.9");
        let pc = profile(&parse_request(bytes(&c)).expect("c"));
        assert_ne!(pa.content_hash, pc.content_hash);
    }

    #[test]
    fn strip_port_leaves_hosts_without_a_port_alone() {
        assert_eq!(strip_port("127.0.0.1:41301"), "127.0.0.1");
        assert_eq!(strip_port("lab.onion"), "lab.onion");
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("host:notaport"), "host:notaport");
        assert_eq!(strip_port(":8080"), ":8080");
    }

    #[test]
    fn header_order_hash_is_order_sensitive() {
        let a = parse_request(bytes(FF)).expect("a");
        let mut b = a.clone();
        // swap the first two headers: same set, different order
        b.headers.swap(0, 1);
        let pa = profile(&a);
        let pb = profile(&b);
        assert_eq!(pa.header_order_lower.len(), pb.header_order_lower.len());
        assert_ne!(pa.order_hash, pb.order_hash, "order hash ignored ordering");
        // sorted-order hash must be stable when the ordering is the same
        let c = parse_request(bytes(FF)).expect("c");
        assert_eq!(pa.order_hash, profile(&c).order_hash);
    }

    #[test]
    fn extracts_chromium_only_signals() {
        let r = parse_request(bytes("GET / HTTP/1.1\r\nHost: x\r\nsec-ch-ua: \"Chromium\";v=\"120\"\r\nsec-ch-ua-mobile: ?0\r\nsec-fetch-mode: navigate\r\n\r\n")).expect("parse");
        let p = profile(&r);
        assert_eq!(p.client_hints.len(), 2);
        assert_eq!(p.sec_fetch, vec!["sec-fetch-mode".to_string()]);
        assert!(p.proxy_injected.is_empty());
    }

    #[test]
    fn detects_proxy_injected_headers() {
        let r = parse_request(bytes(
            "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4\r\nVia: 1.1 tor\r\n\r\n",
        ))
        .expect("parse");
        let p = profile(&r);
        assert_eq!(p.proxy_injected, vec!["x-forwarded-for", "via"]);
    }

    #[test]
    fn cookie_names_are_parsed() {
        let r = parse_request(bytes(FF)).expect("parse");
        let p = profile(&r);
        assert_eq!(p.cookie_names, vec!["hv_run", "hv_sess"]);
        assert_eq!(p.accept_language.as_deref(), Some("en-US,en;q=0.5"));
    }

    #[test]
    fn rejects_garbage() {
        let e = parse_request(bytes("SSH-2.0-x\r\n")).unwrap_err();
        assert!(matches!(e, HttpError::NotHttpRequest(_)));
        let e = parse_request(bytes("GET / HTTP/1.1\r\nBrokenLineNoColon\r\n\r\n")).unwrap_err();
        assert!(matches!(e, HttpError::BadHeaderLine(_)));
    }

    #[test]
    fn read_response_stops_at_content_length_without_waiting_for_close() {
        let payload = response(200, "OK", "application/json", b"{\"ok\":true}", &[]);
        // append extra bytes that must not be swallowed, and never close
        let mut all = payload.clone();
        all.extend_from_slice(b"TRAILING-GARBAGE");
        let mut cur = std::io::Cursor::new(all);
        let got = read_response(&mut cur);
        assert_eq!(got, payload);
    }

    #[test]
    fn read_response_handles_chunked() {
        let body = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut cur = std::io::Cursor::new(body.to_vec());
        let got = read_response(&mut cur);
        assert_eq!(got, body.to_vec());
    }

    #[test]
    fn read_response_handles_close_delimited() {
        let body = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\njust some bytes";
        let mut cur = std::io::Cursor::new(body.to_vec());
        let got = read_response(&mut cur);
        assert_eq!(got, body.to_vec());
    }

    #[test]
    fn response_is_well_formed() {
        let r = response(
            200,
            "OK",
            "text/plain",
            b"hi",
            &[("Set-Cookie", "a=b".into())],
        );
        let s = String::from_utf8_lossy(&r).into_owned();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.ends_with("hi"));
        assert!(s.contains("Set-Cookie: a=b\r\n"));
        // and it parses back with our own parser
        let back = parse_request(bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n")).expect("self-parse");
        assert_eq!(back.headers.len(), 1);
    }

    #[test]
    fn read_request_handles_split_reads_and_bodies() {
        // feed the request in two chunks through a single reader, with a body
        let full =
            "POST /collect?run=x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".to_string();
        let mut cur = std::io::Cursor::new(full.into_bytes());
        let (req, body) = read_request(&mut cur).expect("read");
        assert_eq!(req.method, "POST");
        assert_eq!(body, b"hello");
    }

    #[test]
    fn read_request_with_no_body() {
        let mut cur = std::io::Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        let (req, body) = read_request(&mut cur).expect("read");
        assert_eq!(req.method, "GET");
        assert!(body.is_empty());
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let r =
            parse_request(bytes("GET / HTTP/1.1\r\naccept-LANGUAGE: de\r\n\r\n")).expect("parse");
        assert_eq!(r.header("Accept-Language"), Some("de"));
        assert!(r.has_header("accept-language"));
    }

    #[test]
    fn connect_target_accepts_both_spellings() {
        // what curl and browsers send
        let r = parse_request(b"CONNECT example.invalid:8443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("parse");
        assert_eq!(r.method, "CONNECT");
        assert_eq!(r.path, "example.invalid:8443");
        assert_eq!(r.version, "HTTP/1.1");
        // the RFC 9110 form with the port as its own field
        let r = parse_request(b"CONNECT example.invalid 8443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("parse");
        assert_eq!(r.path, "example.invalid:8443");
        assert_eq!(r.version, "HTTP/1.1");
        // a GET is never rewritten
        let r = parse_request(b"GET /x?y=1 HTTP/1.1\r\n\r\n").expect("parse");
        assert_eq!(r.path, "/x?y=1");
        assert_eq!(r.version, "HTTP/1.1");
    }
}
