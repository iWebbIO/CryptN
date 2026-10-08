//! Hand-rolled HTTP/1.1 client with byte-exact request emission.
//!
//! No framework normalization: the caller composes headers in exactly the
//! order and casing wanted on the wire, and this module writes them verbatim.
//! Connection lifetimes are bounded (30–120s, jittered per install) — no
//! hours-long flows, per the flow-shaping discipline.

use std::time::Duration;

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::parse::percent_decode;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    /// Server closed the connection mid-response.
    ConnectionClosed,
    /// Response unparseable (status line malformed).
    Malformed,
    /// Keep-alive said the connection would persist but the server closed.
    StaleKeepAlive,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::ConnectionClosed => write!(f, "connection closed"),
            ClientError::Malformed => write!(f, "malformed response"),
            ClientError::StaleKeepAlive => write!(f, "stale keep-alive"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// One client connection to the persona front. Owns the TCP stream and
/// enforces a jittered lifetime budget on construction.
pub struct HttpClient {
    stream: TcpStream,
    /// Whether the connection is still usable for another request.
    alive: bool,
    /// Server signalled keep-alive on the last response.
    server_keepalive: bool,
    /// Lifetime budget chosen at connect time (30–120s, like a browser's
    /// pooled connection).
    budget: Duration,
    born: std::time::Instant,
}

impl HttpClient {
    pub async fn connect(addr: &str) -> Result<HttpClient, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        // Jittered lifetime budget (30–120s) for flow shaping. OS entropy so
        // no scanner flag pattern-matches a userspace PRNG seed.
        let budget = Duration::from_secs(30 + (rand::rngs::OsRng.next_u32() % 91) as u64);
        Ok(HttpClient {
            stream,
            alive: true,
            server_keepalive: false,
            budget,
            born: std::time::Instant::now(),
        })
    }

    /// Whether this connection may still carry a request.
    pub fn usable(&self) -> bool {
        self.alive && self.born.elapsed() < self.budget
    }

    fn retire(&mut self) {
        self.alive = false;
    }

    /// Send a request and read the full response.
    ///
    /// `headers` must include `Host` (HTTP/1.1) and a body-framing header when
    /// a body is present — the caller owns every byte of the request.
    pub async fn request(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), ClientError> {
        if !self.usable() {
            return Err(ClientError::StaleKeepAlive);
        }
        let mut req = Vec::with_capacity(512 + body.map(|b| b.len()).unwrap_or(0));
        req.extend_from_slice(method.as_bytes());
        req.push(b' ');
        req.extend_from_slice(target.as_bytes());
        req.extend_from_slice(b" HTTP/1.1\r\n");
        for (n, v) in headers {
            req.extend_from_slice(n.as_bytes());
            req.extend_from_slice(b": ");
            req.extend_from_slice(v.as_bytes());
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"\r\n");
        if let Some(b) = body {
            req.extend_from_slice(b);
        }
        self.stream.write_all(&req).await?;
        self.stream.flush().await?;
        self.read_response(method == "HEAD").await
    }

    async fn read_response(
        &mut self,
        head_only: bool,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), ClientError> {
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut pos = 0usize;
        // Read until CRLFCRLF.
        let head_end = loop {
            if let Some(i) = find_subsequence(&buf[pos..], b"\r\n\r\n") {
                break pos + i;
            }
            pos = buf.len().saturating_sub(3);
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(if buf.is_empty() {
                    ClientError::ConnectionClosed
                } else {
                    ClientError::Malformed
                });
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 128 * 1024 {
                return Err(ClientError::Malformed);
            }
        };

        let head = &buf[..head_end];
        let mut lines = head.split(|&b| b == b'\n');
        let status_line = lines.next().ok_or(ClientError::Malformed)?;
        let status_line = trim_cr(status_line);
        // "HTTP/1.1 200 OK"
        let sp = status_line.split(|&b| b == b' ').collect::<Vec<&[u8]>>();
        if sp.len() < 2 || !sp[0].starts_with(b"HTTP/1.") {
            return Err(ClientError::Malformed);
        }
        let code: u16 = std::str::from_utf8(sp[1])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(ClientError::Malformed)?;

        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            let line = trim_cr(line);
            if line.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(line) {
                if let Some((n, v)) = s.split_once(':') {
                    headers.push((n.to_string(), v.trim().to_string()));
                }
            }
        }

        let header = |name: &str| -> Option<String> {
            headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };

        let conn = header("connection").unwrap_or_default().to_lowercase();
        self.server_keepalive = !conn.split(',').any(|t| t.trim() == "close");

        // Bodies: 304 and 1xx have none; HEAD has none; otherwise framed.
        let no_body_status = (100..200).contains(&code) || code == 204 || code == 304;
        if head_only || no_body_status {
            if !self.server_keepalive {
                self.retire();
            }
            return Ok((code, headers, Vec::new()));
        }

        let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
        if let Some(te) = header("transfer-encoding") {
            if te.to_lowercase().contains("chunked") {
                // May need more data; loop until decode succeeds.
                loop {
                    match decode_chunked(&body) {
                        Some(decoded) => {
                            if !self.server_keepalive {
                                self.retire();
                            }
                            return Ok((code, headers, decoded));
                        }
                        None => {
                            let mut chunk = [0u8; 4096];
                            let n = self.stream.read(&mut chunk).await?;
                            if n == 0 {
                                return Err(ClientError::Malformed);
                            }
                            body.extend_from_slice(&chunk[..n]);
                        }
                    }
                }
            }
        }
        if let Some(cl) = header("content-length") {
            let want: usize = cl.trim().parse().map_err(|_| ClientError::Malformed)?;
            while body.len() < want {
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).await?;
                if n == 0 {
                    return Err(ClientError::ConnectionClosed);
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(want);
        }
        // No CL and no chunking: read-until-close (implies close).
        if header("content-length").is_none() {
            loop {
                let mut chunk = [0u8; 4096];
                match self.stream.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            self.retire();
            return Ok((code, headers, body));
        }

        if !self.server_keepalive {
            self.retire();
        }
        Ok((code, headers, body))
    }
}

fn trim_cr(b: &[u8]) -> &[u8] {
    if b.last() == Some(&b'\r') {
        &b[..b.len() - 1]
    } else {
        b
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode a chunked body; `None` = incomplete (more network reads needed).
fn decode_chunked(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = find_subsequence(&data[i..], b"\r\n")? + i;
        let size_str = std::str::from_utf8(&data[i..line_end]).ok()?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let size = usize::from_str_radix(size_str, 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            // Expect final CRLF (trailers would be before it; tolerate both).
            if data.len() >= i + 2 {
                return Some(out);
            }
            return None;
        }
        if data.len() < i + size + 2 {
            return None;
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2; // skip chunk + CRLF
    }
}

/// Re-export for callers composing query strings.
pub fn decode_query_value(v: &str) -> String {
    percent_decode(v).unwrap_or_else(|| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_decoding() {
        let data = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(data).unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"4\r\nWiki").is_none());
        assert!(decode_chunked(b"zz\r\nxx\r\n0\r\n\r\n").is_none());
    }

    #[test]
    fn subsequence() {
        assert_eq!(find_subsequence(b"abc\r\n\r\nx", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subsequence(b"abc", b"\r\n\r\n"), None);
    }
}
