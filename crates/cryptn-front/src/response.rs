//! Response model: an ordered list of headers serialized exactly as built.
//!
//! No framework normalization, no automatic Content-Length, no header
//! reordering — the persona decides every byte, and this type guarantees the
//! wire matches those decisions.

use crate::reason;

#[derive(Debug, Clone)]
pub struct Response {
    pub code: u16,
    /// Emitted in this exact order and casing.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(code: u16) -> Response {
        Response {
            code,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.push_header(name, value.into());
        self
    }

    pub fn push_header(&mut self, name: &str, value: impl Into<String>) {
        let value: String = value.into();
        // Header-injection guard: values may not carry CR/LF.
        let clean: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        self.headers.push((name.to_string(), clean));
    }

    pub fn body(mut self, bytes: impl Into<Vec<u8>>) -> Response {
        self.body = bytes.into();
        self
    }

    /// The response as raw bytes. `http09` emits only the body (no status line
    /// or headers), like a real 0.9 answer.
    pub fn serialize(&self, http09: bool, omit_body: bool) -> Vec<u8> {
        if http09 {
            return self.body.clone();
        }
        let mut out = Vec::with_capacity(256 + self.body.len());
        let status = format!("HTTP/1.1 {} {}\r\n", self.code, reason(self.code));
        out.extend_from_slice(status.as_bytes());
        for (n, v) in &self.headers {
            out.extend_from_slice(n.as_bytes());
            out.push(b':');
            out.push(b' ');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\r');
            out.push(b'\n');
        }
        out.push(b'\r');
        out.push(b'\n');
        if !omit_body {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// Convenience builder mirroring how persona code composes stock replies.
#[derive(Debug, Default)]
pub struct ResponseBuilder {
    code: Option<u16>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl ResponseBuilder {
    pub fn status(mut self, code: u16) -> Self {
        self.code = Some(code);
        self
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        let mut r = Response::new(0);
        r.push_header(name, value);
        self.headers.extend(r.headers);
        self
    }

    pub fn body(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.body = bytes.into();
        self
    }

    pub fn build(self) -> Response {
        Response {
            code: self.code.unwrap_or(200),
            headers: self.headers,
            body: self.body,
        }
    }
}
