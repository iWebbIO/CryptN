//! The capability dispatcher: the single hidden seam between the webserver
//! persona and the tunnel API.
//!
//! `/<capability-secret>/api/...` is the only path that behaves differently
//! from a stock Apache box — and for anyone without valid, fresh crypto it
//! behaves *identically too*: the stock 404, byte-for-byte. The secret is
//! 128 bits of OS entropy, regenerated per install; scanning for it is
//! hopeless, and probing it yields "nothing here".

use std::sync::Arc;

use cryptn_front::{Request, Response};
use cryptn_persona::PersonaConfig;

use crate::state::AppState;

/// True when the request targets our hidden API (right secret, /api/ prefix).
pub fn is_capability_path(req: &Request, secret: &str) -> bool {
    req.path.starts_with(&format!("/{secret}/api/"))
}

/// Stock 404 via the persona (byte-identical to the front's own 404).
pub fn stock_404(req: &Request, cfg: &PersonaConfig, date: &str) -> Response {
    let host = req
        .header("host")
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_else(|| "localhost".into());
    let port = req
        .header("host")
        .and_then(|h| h.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(80);
    cryptn_persona::error_pages::error_response(
        404,
        req.method.as_str(),
        &cfg.server_banner,
        &host,
        port,
        true,
        None,
        date,
    )
}

/// Dispatch a capability-path request to the tunnel API.
pub async fn dispatch(req: &Request, state: &Arc<AppState>) -> Response {
    let date = cryptn_front::date::httpdate_now();
    let persona = state.persona.clone();

    // Only POST/GET/DELETE exist on the API; other methods get the stock
    // 405/501 semantics a static server would give (still persona-shaped).
    if !matches!(
        req.method,
        cryptn_front::Method::Get | cryptn_front::Method::Post | cryptn_front::Method::Delete
    ) {
        return stock_404(req, &persona, &date);
    }

    // Path layout under the secret: /api/v1/<resource>[/...].
    let api = req
        .path
        .strip_prefix(&format!("/{}/api/", state.capability_secret))
        .unwrap_or("");
    let segments: Vec<&str> = api.split('/').filter(|s| !s.is_empty()).collect();

    let resp = match (req.method.clone(), segments.as_slice()) {
        (cryptn_front::Method::Post, ["v1", "session"]) => {
            crate::api::post_session(state, req).await
        }
        (cryptn_front::Method::Post, ["v1", "messages"]) => {
            crate::api::post_message(state, req).await
        }
        (cryptn_front::Method::Get, ["v1", "conversations", id, "messages"]) => {
            crate::api::get_messages(state, req, id).await
        }
        (cryptn_front::Method::Delete, ["v1", "session"]) => {
            crate::api::delete_session(state, req).await
        }
        // Everything else at the capability path: the path "does not exist".
        _ => stock_404(req, &persona, &date),
    };
    resp
}
