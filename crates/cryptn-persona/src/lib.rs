//! The Apache2-on-Ubuntu persona: byte-exact stock webserver behavior.
//!
//! Every literal in this crate is sourced from the real thing: the default
//! page is `debian/index.html` from the Ubuntu apache2 packaging (the
//! 2022-03-22 revision, embedded byte-exact); the error pages come from
//! `get_canned_error_string()`, `ap_send_error_response()` and
//! `ap_psignature()` in httpd 2.4.58 (`modules/http/http_protocol.c` and
//! `server/core.c`, quoted verbatim); the header order/casing, Keep-Alive
//! semantics and method matrix follow httpd defaults
//! (`MaxKeepAliveRequests 100`, `KeepAliveTimeout 5`, `Timeout 300`,
//! `LimitRequestLine/FieldSize 8190`, `LimitRequestFields 100`).
//!
//! The persona answers *every* request that is not the tunnel's — which is
//! most of the internet's scans — exactly as a forgotten Ubuntu box would.

pub mod assets;
pub mod error_pages;
pub mod headers;
pub mod icons;
pub mod persona;
pub mod static_files;

pub use persona::{handle as persona_handle, PersonaConfig};
