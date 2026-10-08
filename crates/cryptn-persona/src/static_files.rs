//! Static file serving for the document root `/var/www/html` — which on a
//! fresh install contains exactly one file: `index.html`.

use cryptn_front::Response;

use crate::error_pages::error_response;
use crate::headers::{push_static_headers, SERVER_BANNER};

/// A persona-configured install: fixed stat values for the default page so
/// Last-Modified/ETag are stable per install (regenerated at deploy).
#[derive(Debug, Clone)]
pub struct InstallFingerprint {
    pub inode: u64,
    pub size: u64,
    pub mtime: u64,
    /// IMF-fixdate of the install's default-page mtime.
    pub mtime_httpdate: String,
}

/// The fixed identity of the embedded default page across requests.
pub fn default_page_fingerprint() -> InstallFingerprint {
    InstallFingerprint {
        inode: 0x29cd,
        size: crate::assets::DEFAULT_PAGE.len() as u64,
        mtime: 0x6603ac8f,
        mtime_httpdate: "Tue, 26 Mar 2024 10:21:35 GMT".to_string(),
    }
}

/// Conditional-request evaluation: returns Some(304) / Some(206) / None.
pub enum Conditional {
    NotModified,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
    None,
}

/// Evaluate `If-Modified-Since` / `If-None-Match` / `Range` for a static
/// body, the way mod_http does.
pub fn evaluate_conditional(
    etag: &str,
    mtime_secs: u64,
    if_modified_since: Option<&str>,
    if_none_match: Option<&str>,
    range: Option<&str>,
    size: u64,
) -> Conditional {
    // If-None-Match wins over If-Modified-Since.
    let mut not_modified = false;
    if let Some(inm) = if_none_match {
        // Weak comparison; `*` matches anything.
        not_modified = inm.trim() == "*" || inm.split(',').any(|t| t.trim() == etag);
    } else if let Some(ims) = if_modified_since {
        if let Some(secs) = cryptn_front::date::parse_httpdate(ims) {
            not_modified = secs >= mtime_secs;
        }
    }
    if not_modified {
        return Conditional::NotModified;
    }
    if let Some(range) = range {
        return parse_range(range, size);
    }
    Conditional::None
}

/// Parse a single-range `Range: bytes=...` header (multi-range is rare;
/// unsatisfiable → 416 with `Content-Range: bytes */size`).
pub fn parse_range(range: &str, size: u64) -> Conditional {
    let spec = match range.strip_prefix("bytes=") {
        Some(s) => s,
        None => return Conditional::None, // unknown unit: ignore, serve 200
    };
    let spec = spec.split(',').next().unwrap_or("").trim();
    let (start, end) = match spec.split_once('-') {
        Some((s, e)) if !s.is_empty() && !e.is_empty() => {
            match (s.parse::<u64>(), e.parse::<u64>()) {
                (Ok(a), Ok(b)) => (Some(a), Some(b)),
                _ => return Conditional::None,
            }
        }
        Some((s, "")) if !s.is_empty() => match s.parse::<u64>() {
            Ok(a) => (Some(a), None),
            Err(_) => return Conditional::None,
        },
        Some(("", e)) => match e.parse::<u64>() {
            // suffix range: last N bytes
            Ok(n) if n == 0 || n >= size => return Conditional::Unsatisfiable,
            Ok(n) => (Some(size - n), Some(size - 1)),
            Err(_) => return Conditional::None,
        },
        _ => return Conditional::None,
    };
    let (start, end) = match (start, end) {
        (Some(s), Some(e)) if s <= e && s < size => (s, e.min(size - 1)),
        (Some(s), None) if s < size => (s, size - 1),
        _ => return Conditional::Unsatisfiable,
    };
    if size == 0 {
        return Conditional::Unsatisfiable;
    }
    Conditional::Partial { start, end }
}

/// Serve `GET/HEAD /` — the default page with stock static-file semantics:
/// conditional 304, range 206/416, HEAD without body.
#[allow(clippy::too_many_arguments)] // conditional-request evaluation needs the full header set
pub fn serve_default_page(
    etag: &str,
    mtime_secs: u64,
    mtime_httpdate: &str,
    if_modified_since: Option<&str>,
    if_none_match: Option<&str>,
    range: Option<&str>,
    date: &str,
    host: &str,
    port: u16,
    keep_alive: bool,
) -> Response {
    let bytes = crate::assets::DEFAULT_PAGE;
    match evaluate_conditional(
        etag,
        mtime_secs,
        if_modified_since,
        if_none_match,
        range,
        bytes.len() as u64,
    ) {
        Conditional::NotModified => {
            let mut r = Response::new(304);
            r.push_header("Date", date);
            r.push_header("Server", SERVER_BANNER);
            if keep_alive {
                r.push_header("Keep-Alive", "timeout=5, max=100");
                r.push_header("Connection", "Keep-Alive");
            }
            r
        }
        Conditional::Unsatisfiable => {
            let mut r = Response::new(416);
            r.push_header("Date", date);
            r.push_header("Server", SERVER_BANNER);
            r.push_header("Content-Range", format!("bytes */{}", bytes.len()));
            r.body = crate::error_pages::error_page(416, "GET", SERVER_BANNER, host, port);
            r.push_header("Content-Length", r.body.len().to_string());
            if keep_alive {
                r.push_header("Keep-Alive", "timeout=5, max=100");
                r.push_header("Connection", "Keep-Alive");
            }
            r.push_header("Content-Type", "text/html; charset=iso-8859-1");
            r
        }
        Conditional::Partial { start, end } => {
            let start = start as usize;
            let end = end as usize;
            let mut r = Response::new(206);
            r.push_header("Date", date);
            r.push_header("Server", SERVER_BANNER);
            r.push_header("Last-Modified", mtime_httpdate);
            r.push_header("ETag", etag);
            r.push_header("Accept-Ranges", "bytes");
            r.push_header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, end, bytes.len()),
            );
            r.push_header("Content-Length", (end - start + 1).to_string());
            if keep_alive {
                r.push_header("Keep-Alive", "timeout=5, max=100");
                r.push_header("Connection", "Keep-Alive");
            }
            r.push_header("Content-Type", "text/html; charset=UTF-8");
            r.body = bytes[start..=end].to_vec();
            r
        }
        Conditional::None => {
            let mut r = Response::new(200);
            r.body = bytes.to_vec();
            push_static_headers(&mut r, date, mtime_httpdate, etag, keep_alive);
            r.push_header("Content-Type", "text/html; charset=UTF-8");
            r
        }
    }
}

/// 404 for anything else in the document root.
pub fn serve_docroot_404(date: &str, host: &str, port: u16, keep_alive: bool) -> Response {
    error_response(
        404,
        "GET",
        SERVER_BANNER,
        host,
        port,
        keep_alive,
        None,
        date,
    )
}
