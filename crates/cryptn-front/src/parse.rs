//! Request parsing with webserver-shaped strictness.
//!
//! Every rejection here mirrors what a stock Apache 2.4 on Ubuntu does: 400 on
//! malformed lines and bad %-escapes, 414 on long request lines, 400 on
//! oversized/duplicate-conflicting headers, 408 when a started request stalls,
//! 501 for unknown transfer-codings. The goal is that a protocol fuzzer sees
//! the same rejections a real box gives, not "library permissiveness".

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;

use crate::{Method, Version};

/// Apache defaults: `LimitRequestLine`/`LimitRequestFieldSize` are 8190 bytes
/// (counting the line content, not the CRLF), `LimitRequestFields` is 100,
/// `Timeout` is 300s, `KeepAliveTimeout` is 5s.
pub const MAX_REQUEST_LINE: usize = 8190;
pub const MAX_FIELD_SIZE: usize = 8190;
pub const MAX_FIELDS: usize = 100;

/// What went wrong reading/parsing a request.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Peer closed before sending anything (or keep-alive idle timeout):
    /// close silently, exactly like Apache does.
    SilentClose,
    /// A request had started arriving and then stalled: 408 page, then close.
    Timeout(u16),
    /// Malformed request line / headers: the carried page, then close.
    Malformed(u16),
    /// Request entity over the configured cap: 413, then close.
    EntityTooLarge,
}

impl ParseError {
    pub fn status(&self) -> Option<u16> {
        match self {
            ParseError::SilentClose => None,
            ParseError::Timeout(c) | ParseError::Malformed(c) => Some(*c),
            ParseError::EntityTooLarge => Some(413),
        }
    }
}

/// A fully parsed request, plus the raw bytes needed for faithful echoing.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub version: Version,
    /// The request-target exactly as received (origin- or absolute-form).
    pub target: String,
    /// Percent-decoded, dot-segment-resolved path.
    pub path: String,
    /// Raw query string, if any (undecoded).
    pub query: Option<String>,
    /// Header fields in received order, names exactly as cased on the wire.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Exact bytes of the request line + header section (TRACE echo).
    pub raw_head: Vec<u8>,
    /// True when the request signalled `Expect: 100-continue` (1.1 only).
    pub expects_continue: bool,
}

impl Request {
    /// Case-insensitive first-value lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values for a header, in order.
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Query parameter by name, first occurrence (value percent-decoded).
    pub fn query_param(&self, name: &str) -> Option<String> {
        let q = self.query.as_ref()?;
        for pair in q.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if k.eq_ignore_ascii_case(name) {
                return percent_decode(v);
            }
        }
        None
    }
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Strict percent-decoding: every `%` must be followed by two hex digits.
/// Returns `None` on a malformed escape (Apache answers 400).
pub fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let h = hex_val(bytes.get(i + 1).copied()?)?;
                let l = hex_val(bytes.get(i + 2).copied()?)?;
                out.push(h << 4 | l);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Dot-segment removal preserving `//` (Apache's `ap_getparents` does not
/// merge double slashes either).
pub fn remove_dot_segments(path: &str) -> String {
    if !path.contains('.') {
        return path.to_string();
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    // A leading `..` pops nothing (clamped at root, like Apache).
    let mut joined = out.join("/");
    if path.starts_with('/') && !joined.starts_with('/') {
        joined.insert(0, '/');
    }
    if path.ends_with('/') && !joined.ends_with('/') {
        joined.push('/');
    }
    joined
}

/// Buffered line reader over the receive half of a TCP stream with explicit
/// timeout handling: an idle read (no bytes of this request yet) closes
/// silently; a partial line that stalls is a protocol error.
pub struct HeadReader {
    stream: OwnedReadHalf,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    got_any_bytes: bool,
}

impl HeadReader {
    pub fn new(stream: OwnedReadHalf) -> Self {
        HeadReader {
            stream,
            buf: vec![0u8; 8192],
            start: 0,
            end: 0,
            got_any_bytes: false,
        }
    }

    /// Whether any bytes of the current request have arrived yet.
    pub fn saw_bytes(&self) -> bool {
        self.got_any_bytes
    }

    /// Read bytes into the buffer, honoring timeouts. Zero bytes read with no
    /// prior bytes of this request = silent close.
    async fn fill(&mut self, timeout: Duration) -> Result<usize, ParseError> {
        let fut = self.stream.read(&mut self.buf[self.end..]);
        match tokio::time::timeout(timeout, fut).await {
            Err(_) => Err(if self.got_any_bytes {
                ParseError::Timeout(408)
            } else {
                ParseError::SilentClose
            }),
            Ok(Err(_)) | Ok(Ok(0)) => Err(if self.got_any_bytes {
                ParseError::Timeout(408)
            } else {
                ParseError::SilentClose
            }),
            Ok(Ok(n)) => {
                if n > 0 {
                    self.got_any_bytes = true;
                }
                self.end += n;
                Ok(n)
            }
        }
    }

    /// Read one LF-terminated line (returned without the terminator,
    /// CR stripped if present). Exceeding `cap` yields `Malformed(over)`.
    async fn read_line(
        &mut self,
        cap: usize,
        over: u16,
        timeout: Duration,
    ) -> Result<Vec<u8>, ParseError> {
        let mut line: Vec<u8> = Vec::with_capacity(128);
        loop {
            while self.start < self.end {
                let b = self.buf[self.start];
                if b == b'\n' {
                    self.start += 1;
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(line);
                }
                line.push(b);
                self.start += 1;
                if line.len() > cap {
                    return Err(ParseError::Malformed(over));
                }
            }
            self.end = 0;
            self.start = 0;
            self.fill(timeout).await?;
        }
    }

    /// Read exactly `n` bytes of body.
    async fn read_exact_body(
        &mut self,
        n: usize,
        cap: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, ParseError> {
        if n > cap {
            return Err(ParseError::EntityTooLarge);
        }
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            while self.start < self.end && out.len() < n {
                out.push(self.buf[self.start]);
                self.start += 1;
            }
            if out.len() == n {
                return Ok(out);
            }
            self.end = 0;
            self.start = 0;
            self.fill(timeout).await?;
        }
        Ok(out)
    }

    /// Emit `100 Continue` (the reader owns the read half, so the caller
    /// supplies the write half for this one frame).
    pub async fn send_continue(&mut self, write: &mut tokio::net::tcp::OwnedWriteHalf) {
        let _ = write.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        let _ = write.flush().await;
    }

    /// Reset per-request state for the next keep-alive iteration.
    fn reset_request(&mut self) {
        self.got_any_bytes = false;
    }
}

pub struct HeadLimits {
    pub max_line: usize,
    pub max_field: usize,
    pub max_fields: usize,
    pub max_body: usize,
    /// Timeout once a request has started (Apache `Timeout`, 300s default).
    pub request_timeout: Duration,
    /// Timeout while waiting for the first byte of the *next* request on a
    /// keep-alive connection (Apache `KeepAliveTimeout`, 5s default).
    pub idle_timeout: Duration,
}

impl Default for HeadLimits {
    fn default() -> Self {
        HeadLimits {
            max_line: MAX_REQUEST_LINE,
            max_field: MAX_FIELD_SIZE,
            max_fields: MAX_FIELDS,
            max_body: 10 * 1024 * 1024,
            request_timeout: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(5),
        }
    }
}

/// A request head: everything before the body.
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: Method,
    pub version: Version,
    pub target: String,
    pub headers: Vec<(String, String)>,
    raw_head: Vec<u8>,
    /// Body framing resolved from the headers.
    framing: Framing,
}

#[derive(Debug, Clone)]
enum Framing {
    Empty,
    ContentLength(usize),
    Chunked,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_body(&self) -> bool {
        !matches!(self.framing, Framing::Empty)
    }
}

/// Parse one request. Composes `read_head` + `read_body` (the server calls the
/// two phases separately so `Expect: 100-continue` can be honored between
/// them, exactly like Apache).
pub async fn read_request(
    reader: &mut HeadReader,
    limits: &HeadLimits,
) -> Result<Request, ParseError> {
    let head = read_head(reader, limits).await?;
    read_body(reader, head, limits).await
}

/// Parse one request head. The read timeout starts at `idle_timeout` until
/// the first byte arrives, then switches to `request_timeout`.
pub async fn read_head(
    reader: &mut HeadReader,
    limits: &HeadLimits,
) -> Result<RequestHead, ParseError> {
    let line = reader
        .read_line(limits.max_line, 414, limits.idle_timeout)
        .await?;
    reader.reset_request(); // any stall from here on is mid-request

    let mut raw_head = Vec::with_capacity(1024);
    raw_head.extend_from_slice(&line);
    raw_head.extend_from_slice(b"\r\n");

    let (method, target, version) = parse_request_line(&line)?;

    // HTTP/0.9 is a bare request line: no headers, no body.
    if version == Version::Http09 {
        return Ok(RequestHead {
            method,
            version,
            target,
            headers: Vec::new(),
            raw_head,
            framing: Framing::Empty,
        });
    }

    // Header fields.
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut saw_blank = false;
    for _ in 0..limits.max_fields {
        let hl = reader
            .read_line(limits.max_field, 400, limits.request_timeout)
            .await?;
        if hl.is_empty() {
            saw_blank = true;
            break;
        }
        if hl.first() == Some(&b' ') || hl.first() == Some(&b'\t') {
            return Err(ParseError::Malformed(400)); // obs-fold rejected
        }
        let (name, value) = parse_header_field(&hl)?;
        raw_head.extend_from_slice(&hl);
        raw_head.extend_from_slice(b"\r\n");
        headers.push((name, value));
    }
    if !saw_blank {
        return Err(ParseError::Malformed(400)); // too many fields
    }

    // HTTP/1.1 requires exactly one Host header.
    if version == Version::Http11 {
        let hosts = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
            .count();
        if hosts != 1 {
            return Err(ParseError::Malformed(400));
        }
    }

    // Body framing. Content-Length + Transfer-Encoding = 400
    // (request-smuggling defense). Non-chunked TE = 501.
    let mut framing = Framing::Empty;
    let mut saw_te = false;
    let mut cl: Option<usize> = None;
    for (n, v) in &headers {
        if n.eq_ignore_ascii_case("transfer-encoding") {
            if cl.is_some() || saw_te {
                return Err(ParseError::Malformed(400));
            }
            let ok = !v.is_empty()
                && v.split(',')
                    .map(|t| t.trim())
                    .all(|t| t.eq_ignore_ascii_case("chunked"));
            if !ok {
                return Err(ParseError::Malformed(501));
            }
            saw_te = true;
            framing = Framing::Chunked;
        } else if n.eq_ignore_ascii_case("content-length") {
            let sv = v.trim();
            if sv.is_empty() || !sv.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::Malformed(400));
            }
            let this_len: usize = sv.parse().map_err(|_| ParseError::Malformed(400))?;
            if saw_te {
                return Err(ParseError::Malformed(400));
            }
            if let Some(prev) = cl {
                if prev != this_len {
                    return Err(ParseError::Malformed(400));
                }
            }
            cl = Some(this_len);
            framing = Framing::ContentLength(this_len);
        }
    }

    Ok(RequestHead {
        method,
        version,
        target,
        headers,
        raw_head,
        framing,
    })
}

/// Read the body of a request whose head was parsed by `read_head`.
pub async fn read_body(
    reader: &mut HeadReader,
    head: RequestHead,
    limits: &HeadLimits,
) -> Result<Request, ParseError> {
    let body = match head.framing {
        Framing::Empty => Vec::new(),
        Framing::ContentLength(len) => {
            reader
                .read_exact_body(len, limits.max_body, limits.request_timeout)
                .await?
        }
        Framing::Chunked => read_chunked(reader, limits).await?,
    };

    // Split path/query and decode.
    let (raw_path, query) = split_target(&head.target);
    let path = percent_decode(&raw_path).ok_or(ParseError::Malformed(400))?;
    if path.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return Err(ParseError::Malformed(400));
    }
    let path = remove_dot_segments(&path);

    Ok(Request {
        method: head.method,
        version: head.version,
        target: head.target,
        path,
        query,
        headers: head.headers,
        body,
        raw_head: head.raw_head,
        expects_continue: false, // the server emits 100-continue between head and body
    })
}

fn parse_request_line(line: &[u8]) -> Result<(Method, String, Version), ParseError> {
    if line.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Err(ParseError::Malformed(400));
    }
    let s = std::str::from_utf8(line).map_err(|_| ParseError::Malformed(400))?;
    let parts: Vec<&str> = s.split(' ').collect();
    match parts.len() {
        2 => {
            // HTTP/0.9 was GET-only.
            if parts[0] != "GET" {
                return Err(ParseError::Malformed(400));
            }
            Ok((Method::Get, parts[1].to_string(), Version::Http09))
        }
        3 => {
            let method_tok = parts[0];
            if method_tok.is_empty()
                || !method_tok.bytes().all(is_token_char)
                || parts[1].is_empty()
            {
                return Err(ParseError::Malformed(400));
            }
            let version = match parts[2] {
                "HTTP/1.0" => Version::Http10,
                "HTTP/1.1" => Version::Http11,
                v if v.starts_with("HTTP/") => {
                    let major = v.as_bytes()[5];
                    if major >= b'2' {
                        return Err(ParseError::Malformed(505));
                    }
                    return Err(ParseError::Malformed(400));
                }
                _ => return Err(ParseError::Malformed(400)),
            };
            Ok((Method::parse(method_tok), parts[1].to_string(), version))
        }
        _ => Err(ParseError::Malformed(400)),
    }
}

fn parse_header_field(line: &[u8]) -> Result<(String, String), ParseError> {
    let s = std::str::from_utf8(line).map_err(|_| ParseError::Malformed(400))?;
    let (name, value) = s.split_once(':').ok_or(ParseError::Malformed(400))?;
    if name.is_empty() || !name.bytes().all(is_token_char) {
        return Err(ParseError::Malformed(400));
    }
    let value = value.trim_matches(|c| c == ' ' || c == '\t');
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(ParseError::Malformed(400));
    }
    Ok((name.to_string(), value.to_string()))
}

fn split_target(target: &str) -> (String, Option<String>) {
    // origin-form; absolute-form tolerated and reduced like a proxy does;
    // asterisk-form passes through for `OPTIONS *`.
    let t = if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        }
    } else {
        target
    };
    match t.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (t.to_string(), None),
    }
}

async fn read_chunked(reader: &mut HeadReader, limits: &HeadLimits) -> Result<Vec<u8>, ParseError> {
    let mut out = Vec::new();
    loop {
        let size_line = reader.read_line(128, 400, limits.request_timeout).await?;
        let s = std::str::from_utf8(&size_line).map_err(|_| ParseError::Malformed(400))?;
        let size_str = s.split(';').next().unwrap_or("").trim();
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::Malformed(400));
        }
        let size = usize::from_str_radix(size_str, 16).map_err(|_| ParseError::Malformed(400))?;
        if out.len() + size > limits.max_body {
            return Err(ParseError::EntityTooLarge);
        }
        if size == 0 {
            // trailers until blank line, discarded
            loop {
                let tl = reader.read_line(1024, 400, limits.request_timeout).await?;
                if tl.is_empty() {
                    break;
                }
            }
            return Ok(out);
        }
        let chunk = reader
            .read_exact_body(size, limits.max_body, limits.request_timeout)
            .await?;
        out.extend_from_slice(&chunk);
        let crlf = reader.read_line(2, 400, limits.request_timeout).await?;
        if !crlf.is_empty() {
            return Err(ParseError::Malformed(400));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_normalizes() {
        assert_eq!(percent_decode("%2e%2e/foo"), Some("../foo".to_string()));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(remove_dot_segments("/a/./b/../c/"), "/a/c/");
        assert_eq!(remove_dot_segments("/../../x"), "/x");
        assert_eq!(remove_dot_segments("//double//slash"), "//double//slash");
    }

    #[test]
    fn request_line_parsing() {
        assert!(parse_request_line(b"GET / HTTP/1.1").is_ok());
        assert!(parse_request_line(b"GET /").is_ok());
        assert!(parse_request_line(b"GET").is_err());
        assert!(parse_request_line(b"GET  / HTTP/1.1").is_err());
        assert!(parse_request_line(b"GET / HTTP/2.0").is_err());
        assert!(parse_request_line(b"GE\tT / HTTP/1.1").is_err());
    }

    #[test]
    fn header_parsing() {
        assert_eq!(
            parse_header_field(b"Host: example.com").unwrap(),
            ("Host".to_string(), "example.com".to_string())
        );
        assert_eq!(
            parse_header_field(b"X-Pad:  spaced  ").unwrap(),
            ("X-Pad".to_string(), "spaced".to_string())
        );
        assert!(parse_header_field(b"Bad Header: x").is_err());
        assert!(parse_header_field(b"Colonless").is_err());
        assert!(parse_header_field(b"X-Ctl: o\x00ps").is_err());
    }

    #[test]
    fn target_splitting() {
        assert_eq!(
            split_target("http://example.com/a/b?x=1"),
            ("/a/b".to_string(), Some("x=1".to_string()))
        );
        assert_eq!(split_target("http://example.com"), ("/".to_string(), None));
        assert_eq!(
            split_target("/a?b"),
            ("/a".to_string(), Some("b".to_string()))
        );
        assert_eq!(split_target("*"), ("*".to_string(), None));
    }
}
