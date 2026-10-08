//! Apache 2.4 stock header vocabulary and ordering.
//!
//! Apache emits `Date` and `Server` on every response (mod_headers order is
//! actually: Date first, then Server — fixed by the core filter). Static
//! files additionally carry `Last-Modified`, `ETag`, `Accept-Ranges`,
//! `Content-Length`, keep-alive pair, and `Content-Type` — in that order,
//! as `ap_set_keepalive` + the core output filter produce them.

/// Canonical Ubuntu banner: `Apache/2.4.58 (Ubuntu)`.
pub const SERVER_BANNER: &str = "Apache/2.4.58 (Ubuntu)";

/// Push the stock static-file header set onto a response in Apache's order.
/// `etag` example: `"29cd-61f0e123-614a3b8b9c0000"` (hex inode-ish, hex size,
/// hex mtime — the actual value is per-install and set at deploy).
pub fn push_static_headers(
    r: &mut cryptn_front::Response,
    date: &str,
    last_modified: &str,
    etag: &str,
    keep_alive: bool,
) {
    r.push_header("Date", date);
    r.push_header("Server", SERVER_BANNER);
    r.push_header("Last-Modified", last_modified);
    r.push_header("ETag", etag);
    r.push_header("Accept-Ranges", "bytes");
    r.push_header("Content-Length", r.body.len().to_string());
    if keep_alive {
        r.push_header("Keep-Alive", "timeout=5, max=100");
        r.push_header("Connection", "Keep-Alive");
    } else {
        r.push_header("Connection", "close");
    }
}

/// Content types for the files a stock install serves.
pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=UTF-8",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=UTF-8",
        _ => "text/plain; charset=UTF-8",
    }
}

/// Strong ETag in httpd's format: `"{hexsize}-{hexmtime}"` for
/// `FileETag INode MTime Size`... 2.4 uses all three by default on Linux:
/// `"{inode}-{size}-{mtime}"`, each lowercase hex, wrapped in quotes.
pub fn file_etag(inode: u64, size: u64, mtime: u64) -> String {
    format!("\"{:x}-{:x}-{:x}\"", inode, size, mtime)
}
