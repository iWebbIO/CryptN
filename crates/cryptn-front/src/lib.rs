//! Hand-rolled HTTP/1.1 with byte-exact control.
//!
//! The whole point of this crate is that every byte on the wire is a decision we
//! made, not a framework default: request parsing with webserver-shaped
//! strictness, response serialization that emits headers in exactly the order
//! and casing we choose, and a client with the same discipline.

pub mod client;
pub mod date;
pub mod parse;
pub mod response;
pub mod server;

pub use client::{ClientError, HttpClient};
pub use date::httpdate_now;
pub use parse::{percent_decode, HeadLimits, HeadReader, ParseError, Request};
pub use response::{Response, ResponseBuilder};
pub use server::{serve, BoxHandlerFut, ConnState, ErrorPage, Handled, Handler, ServerConfig};

/// HTTP version seen on the request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Legacy two-token request line (`GET /path`) — no status line in reply.
    Http09,
    Http10,
    Http11,
}

impl Version {
    /// Literal as it appears on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::Http09 => "HTTP/0.9",
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

/// The 8 "standard" methods Apache registers for a stock install, plus anything
/// else a client may send (kept verbatim so persona code can answer 501/405).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    /// Any other token, preserved as received.
    Other(String),
}

impl Method {
    pub fn parse(tok: &str) -> Method {
        match tok {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "CONNECT" => Method::Connect,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
            other => Method::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Other(s) => s.as_str(),
        }
    }
}

/// Reason phrases Apache emits on the status line (2.4.x set).
pub fn reason(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}
