//! cryptn-server library: the whole VPS side, importable for tests.
//!
//! `main.rs` is a thin shell: build state, bind, serve. Everything real
//! lives here so integration tests can drive the full stack in-process.

pub mod api;
pub mod dispatch;
pub mod records;
pub mod state;
pub mod tunnel_state;

use std::sync::Arc;

use cryptn_front::parse::HeadLimits;
use cryptn_front::{serve, ConnState, Handled, Request, Response, ServerConfig};

use state::AppState;

/// Wire the front handler: capability path → tunnel API; persona otherwise.
pub fn front_handler(app: Arc<AppState>) -> cryptn_front::Handler<()> {
    Arc::new(move |_conn: &ConnState, req: &Request, _s: &()| {
        let app = app.clone();
        let is_tunnel = dispatch::is_capability_path(req, &app.capability_secret);
        let req = req.clone();
        Box::pin(async move {
            if is_tunnel {
                let resp = dispatch::dispatch(&req, &app).await;
                Handled::Reply(resp)
            } else {
                let date = cryptn_front::date::httpdate_now();
                let resp = cryptn_persona::persona_handle(&req, &app.persona, &date);
                Handled::Reply(resp)
            }
        }) as cryptn_front::BoxHandlerFut
    })
}

/// Persona-shaped error pages for parse failures.
pub fn front_error_page() -> cryptn_front::ErrorPage {
    Arc::new(|_c: &ConnState, code: u16| {
        let body = cryptn_persona::error_pages::error_page(
            code,
            "GET",
            "Apache/2.4.58 (Ubuntu)",
            "localhost",
            80,
        );
        let mut r = Response::new(code);
        r.push_header("Date", cryptn_front::date::httpdate_now());
        r.push_header("Server", "Apache/2.4.58 (Ubuntu)");
        r.push_header("Content-Length", body.len().to_string());
        r.push_header("Connection", "close");
        r.push_header("Content-Type", "text/html; charset=iso-8859-1");
        r.body = body;
        r
    })
}

/// Serve the full stack on a listener.
pub async fn serve_stack(
    listener: tokio::net::TcpListener,
    app: Arc<AppState>,
) -> std::io::Result<()> {
    let config = Arc::new(ServerConfig {
        limits: HeadLimits::default(),
        max_keepalive_requests: 100,
        handler: front_handler(app),
        error_page: front_error_page(),
        state: (),
    });
    serve(listener, config).await
}

/// Build a complete AppState from deployment identity.
pub fn build_state(
    setup: cryptn_pake::Setup,
    server_file: Vec<u8>,
    capability_secret: String,
    guard: cryptn_egress::EgressGuard,
) -> Arc<AppState> {
    Arc::new(AppState {
        persona: cryptn_persona::PersonaConfig::default(),
        capability_secret,
        setup,
        server_file,
        sessions: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        logins: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        tunnels: tunnel_state::TunnelState::new(guard),
    })
}
