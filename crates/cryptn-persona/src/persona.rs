//! The Apache2-Ubuntu persona: request dispatch with stock behavior.
//!
//! This is the decision tree a fresh `apt install apache2` box runs through
//! for every request — and everything that is not the capability path lands
//! here, so the persona is what scanners, crawlers, and probers meet.

use cryptn_front::{Request, Response};

use crate::error_pages::error_response;
use crate::headers::{file_etag, SERVER_BANNER};
use crate::icons::serve_icons;
use crate::static_files::{default_page_fingerprint, serve_default_page};

/// Persona options (per-install values, generated at deploy).
#[derive(Debug, Clone)]
pub struct PersonaConfig {
    /// e.g. "Apache/2.4.58 (Ubuntu)"
    pub server_banner: String,
    /// Install-stable ETag inputs for the default page.
    pub default_inode: u64,
    pub default_mtime: u64,
    pub default_mtime_httpdate: String,
}

impl Default for PersonaConfig {
    fn default() -> Self {
        let fp = default_page_fingerprint();
        PersonaConfig {
            server_banner: SERVER_BANNER.to_string(),
            default_inode: fp.inode,
            default_mtime: fp.mtime,
            default_mtime_httpdate: fp.mtime_httpdate,
        }
    }
}

/// Extract the Host header's hostname (without port) for the signature
/// footer — `ap_get_server_name` on a stock box with no ServerName resolves
/// to the Host header.
fn hostname_of(req: &Request) -> String {
    req.header("host")
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_else(|| "localhost".to_string())
}

/// The port the *client* connected to, as Apache reports it (ap_get_server_port
/// is the Host header's port, defaulting to 80).
fn port_of(req: &Request) -> u16 {
    req.header("host")
        .and_then(|h| h.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(80)
}

/// Dispatch a request that the capability dispatcher did not claim.
/// `date` is the persona-composed Date header value.
pub fn handle(req: &Request, cfg: &PersonaConfig, date: &str) -> Response {
    let host = hostname_of(req);
    let port = port_of(req);
    let keep_alive = true; // keep-alive handled by the front's connection loop
    let is_http11 = req.version == cryptn_front::Version::Http11;

    // Method matrix for a static document root:
    // GET/HEAD/POST/PUT/DELETE/CONNECT + OPTIONS/TRACE.
    match &req.method {
        cryptn_front::Method::Trace => {
            // TraceEnable On (Ubuntu stock ships no override): the request
            // echoes back 200 with Content-Type message/http.
            let mut body = req.raw_head.clone();
            body.extend_from_slice(b"\r\n"); // trailing blank line
            let mut r = Response::new(200);
            r.push_header("Date", date);
            r.push_header("Server", cfg.server_banner.clone());
            r.push_header("Content-Length", body.len().to_string());
            if !is_http11 {
                r.push_header("Connection", "close");
            }
            r.push_header("Content-Type", "message/http");
            r.body = body;
            r
        }
        cryptn_front::Method::Options => {
            // OPTIONS * (asterisk-form) or OPTIONS /: stock static server
            // answers 200 with Allow: GET,HEAD,POST,OPTIONS,TRACE (the
            // core + autoindex set on /). For other resources it is
            // 405/Allow on the error page.
            let mut r = Response::new(200);
            r.push_header("Date", date);
            r.push_header("Server", cfg.server_banner.clone());
            r.push_header("Allow", "GET,HEAD,POST,OPTIONS,TRACE");
            r.push_header("Content-Length", "0");
            if !is_http11 {
                r.push_header("Connection", "close");
            }
            r
        }
        cryptn_front::Method::Connect => error_response(
            405,
            "CONNECT",
            &cfg.server_banner,
            &host,
            port,
            false,
            Some("GET,HEAD,POST,OPTIONS,TRACE"),
            date,
        ),
        _ => serve_path(req, cfg, date, &host, port, keep_alive),
    }
}

/// Path-based serving under the stock document root.
fn serve_path(
    req: &Request,
    cfg: &PersonaConfig,
    date: &str,
    host: &str,
    port: u16,
    keep_alive: bool,
) -> Response {
    let path = req.path.as_str();

    // POST/PUT/DELETE on static files: stock Apache answers 405 with Allow
    // (or 501 for unknown methods before that).
    let write_method = !matches!(
        req.method,
        cryptn_front::Method::Get | cryptn_front::Method::Head
    );
    if write_method || matches!(req.method, cryptn_front::Method::Other(_)) {
        let method = req.method.as_str();
        let code = if matches!(req.method, cryptn_front::Method::Other(_)) {
            501
        } else {
            405
        };
        return error_response(
            code,
            method,
            &cfg.server_banner,
            host,
            port,
            keep_alive,
            Some("GET,HEAD,POST,OPTIONS,TRACE"),
            date,
        );
    }

    // Directory-normalized paths:
    match path {
        "/" | "/index.html" => {
            let etag = file_etag(
                cfg.default_inode,
                crate::assets::DEFAULT_PAGE.len() as u64,
                cfg.default_mtime,
            );
            serve_default_page(
                &etag,
                cfg.default_mtime,
                &cfg.default_mtime_httpdate,
                req.header("if-modified-since"),
                req.header("if-none-match"),
                req.header("range"),
                date,
                host,
                port,
                keep_alive,
            )
        }
        "/server-status" | "/server-info" => {
            // mod_status not enabled: stock 404. (Scanners love these.)
            error_response(
                404,
                "GET",
                &cfg.server_banner,
                host,
                port,
                keep_alive,
                None,
                date,
            )
        }
        "/manual" | "/manual/" => {
            // apache2-doc not installed: 404.
            error_response(
                404,
                "GET",
                &cfg.server_banner,
                host,
                port,
                keep_alive,
                None,
                date,
            )
        }
        p if p.starts_with("/icons/") => serve_icons(p, date, host, port, keep_alive),
        _ => error_response(
            404,
            "GET",
            &cfg.server_banner,
            host,
            port,
            keep_alive,
            None,
            date,
        ),
    }
}
