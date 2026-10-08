//! `/icons/` — the stock mod_alias Alias path.
//!
//! A fresh `apt install apache2` serves the icon referenced by the default
//! page at `icons/ubuntu-logo.png`; every other name under `/icons/` is the
//! stock 404 (no icon files ship in the minimal package set reachable there).

use cryptn_front::Response;

use crate::error_pages::error_response;
use crate::headers::{content_type, file_etag, push_static_headers, SERVER_BANNER};

/// Serve an `/icons/...` request.
pub fn serve_icons(path: &str, date: &str, host: &str, port: u16, keep_alive: bool) -> Response {
    if path == "/icons/ubuntu-logo.png" {
        let bytes = crate::assets::UBUNTU_LOGO_PNG;
        let mut r = Response::new(200);
        r.body = bytes.to_vec();
        push_static_headers(
            &mut r,
            date,
            "Fri, 22 Mar 2024 09:12:34 GMT",
            &file_etag(0x29cd, bytes.len() as u64, 0x61f0e123),
            keep_alive,
        );
        r.push_header("Content-Type", content_type("x.png"));
        r
    } else {
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
}
