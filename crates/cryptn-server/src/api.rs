//! The API handlers: every response is the persona app's JSON — success
//! shapes and error shapes both. A replayed login is "invalid email or
//! password"; a replayed message is "duplicate message"; a bad token is
//! "session expired". Nothing protocol-shaped ever crosses the wire.

use std::sync::Arc;

use cryptn_front::{Request, Response};
use serde::Deserialize;

use crate::state::{AppState, LiveSession, PendingLogin};
use crate::tunnel_state::UpstreamOutcome;

/// JSON content type for API replies (the app's constant).
const APP_JSON: &str = "application/json; charset=utf-8";

fn json_response(code: u16, body: Vec<u8>, date: &str) -> Response {
    let mut r = Response::new(code);
    r.push_header("Date", date);
    r.push_header("Server", "Apache/2.4.58 (Ubuntu)");
    r.push_header("Content-Length", body.len().to_string());
    r.push_header("Keep-Alive", "timeout=5, max=100");
    r.push_header("Connection", "Keep-Alive");
    r.push_header("Content-Type", APP_JSON);
    r.body = body;
    r
}

fn error_response(code: u16, msg: &'static str) -> Response {
    let date = cryptn_front::date::httpdate_now();
    json_response(code, cryptn_envelope::error_json(msg), &date)
}

#[derive(Deserialize)]
struct PostMessageBody {
    conversation_id: String,
    id: String,
    body: String,
}

/// `POST /<secret>/api/v1/session` — the two-step login.
pub async fn post_session(state: &Arc<AppState>, req: &Request) -> Response {
    #[derive(Deserialize)]
    struct AnyStep {
        flow: Option<String>,
        login1: Option<String>,
        login3: Option<String>,
    }
    let step: AnyStep = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return error_response(401, "invalid email or password"),
    };

    match (step.flow.as_deref(), step.login1, step.login3) {
        (Some("start"), Some(l1), _) => {
            let login1 = match cryptn_envelope::b64_decode(&l1) {
                Some(v) => v,
                None => return error_response(401, "invalid email or password"),
            };
            let mut entropy = rand::rngs::OsRng;
            let (login2, pstate) = match cryptn_pake::server_login_start(
                &mut entropy,
                &state.setup,
                &state.server_file,
                &login1,
            ) {
                Ok(v) => v,
                Err(_) => return error_response(401, "invalid email or password"),
            };
            // Track the pending handshake under a random nonce.
            let mut nonce = [0u8; 16];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            state.gc_logins().await;
            state.logins.lock().await.insert(
                nonce,
                PendingLogin {
                    state: pstate,
                    born: std::time::Instant::now(),
                },
            );
            // Reply carries both the nonce and the challenge, like a real
            // multi-step login carrying state in the payload.
            let body = serde_json::json!({
                "flow": "challenge",
                "request_id": cryptn_envelope::b64url_encode(&nonce),
                "login2": cryptn_envelope::b64_encode(&login2),
            });
            let date = cryptn_front::date::httpdate_now();
            json_response(200, serde_json::to_vec(&body).unwrap(), &date)
        }
        (Some("finish"), _, Some(l3)) => {
            #[derive(Deserialize)]
            struct FinishBody {
                request_id: Option<String>,
                login3: String,
            }
            let _ = l3; // outer parse already holds it
            let fin: FinishBody = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return error_response(401, "invalid email or password"),
            };
            let nonce_b = match fin
                .request_id
                .as_deref()
                .and_then(cryptn_envelope::b64url_decode)
            {
                Some(v) => v,
                None => return error_response(401, "invalid email or password"),
            };
            let mut nonce = [0u8; 16];
            if nonce_b.len() != 16 {
                return error_response(401, "invalid email or password");
            }
            nonce.copy_from_slice(&nonce_b);
            let pending = state.logins.lock().await.remove(&nonce);
            let pstate = match pending {
                Some(p) => p.state,
                None => return error_response(401, "invalid email or password"),
            };
            let login3 = match cryptn_envelope::b64_decode(&fin.login3) {
                Some(v) => v,
                None => return error_response(401, "invalid email or password"),
            };
            let session_key = match cryptn_pake::server_login_finish(pstate, &login3) {
                Ok(k) => k,
                Err(_) => return error_response(401, "invalid email or password"),
            };
            // Session created: id, tokens, records.
            let mut sid = [0u8; 16];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut sid);
            let session = Arc::new(LiveSession {
                id: sid,
                records: crate::records::SessionRecords::from_session_key(&session_key),
                tokens: cryptn_session::TokenAuthority::from_session_key(&session_key),
            });
            let ttl = 3600;
            let token = session.tokens.mint(sid, ttl);
            state.sessions.lock().await.insert(sid, session);
            let body = serde_json::json!({
                "token": cryptn_envelope::b64_encode(&token),
                "expires_in": ttl,
            });
            let date = cryptn_front::date::httpdate_now();
            json_response(200, serde_json::to_vec(&body).unwrap(), &date)
        }
        _ => error_response(401, "invalid email or password"),
    }
}

/// `POST /<secret>/api/v1/messages` — one sealed upstream record.
pub async fn post_message(state: &Arc<AppState>, req: &Request) -> Response {
    // Auth first, like every real API: 401 before any body validation.
    let token = match bearer_token(req) {
        Some(t) => t,
        None => return error_response(401, "session expired"),
    };
    let session = match state.session_for_token(&token).await {
        Some(s) => s,
        None => return error_response(401, "session expired"),
    };
    let body: PostMessageBody = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return error_response(400, "invalid message"),
    };
    let conv_id_b = match cryptn_envelope::b64url_decode(&body.conversation_id) {
        Some(v) if v.len() == 16 => v,
        _ => return error_response(400, "invalid message"),
    };
    let mut conv_id = [0u8; 16];
    conv_id.copy_from_slice(&conv_id_b);
    let counter_b = match cryptn_envelope::b64url_decode(&body.id) {
        Some(v) if v.len() == 8 => v,
        _ => return error_response(400, "invalid message"),
    };
    let counter = u64::from_be_bytes(counter_b.try_into().unwrap());
    let sealed = match cryptn_envelope::b64_decode(&body.body) {
        Some(v) => v,
        None => return error_response(400, "invalid message"),
    };

    match state
        .tunnels
        .handle_upstream(&session.records, &conv_id, counter, &sealed)
        .await
    {
        Ok(UpstreamOutcome::Duplicate) => error_response(409, "duplicate message"),
        Ok(_) => {
            let body = serde_json::json!({ "status": "sent" });
            let date = cryptn_front::date::httpdate_now();
            json_response(201, serde_json::to_vec(&body).unwrap(), &date)
        }
        Err(e) => {
            eprintln!("upstream error: {e}");
            error_response(400, "invalid message")
        }
    }
}

/// `GET /<secret>/api/v1/conversations/{id}/messages?after=&timeout=` —
/// the downstream long-poll.
pub async fn get_messages(state: &Arc<AppState>, req: &Request, id: &str) -> Response {
    let token = match bearer_token(req) {
        Some(t) => t,
        None => return error_response(401, "session expired"),
    };
    let session = match state.session_for_token(&token).await {
        Some(s) => s,
        None => return error_response(401, "session expired"),
    };
    let conv_id_b = match cryptn_envelope::b64url_decode(id) {
        Some(v) if v.len() == 16 => v,
        _ => return error_response(404, "conversation not found"),
    };
    let mut conv_id = [0u8; 16];
    conv_id.copy_from_slice(&conv_id_b);

    let timeout: u64 = req
        .query_param("timeout")
        .and_then(|t| t.parse().ok())
        .unwrap_or(25)
        .min(25);

    let batch = match state
        .tunnels
        .poll_downstream(&session.records, &conv_id, timeout * 1000)
        .await
    {
        Ok(b) => b,
        Err(_) => return error_response(404, "conversation not found"),
    };

    let messages: Vec<cryptn_envelope::MessageOut> = batch
        .iter()
        .map(|(counter, sealed)| cryptn_envelope::wrap_record(&conv_id, *counter, sealed))
        .collect();
    let next = messages
        .last()
        .map(|m| m.id.clone())
        .unwrap_or_else(|| req.query_param("after").unwrap_or_default());
    let body = serde_json::json!({ "messages": messages, "next": next });
    let date = cryptn_front::date::httpdate_now();
    json_response(200, serde_json::to_vec(&body).unwrap(), &date)
}

/// `DELETE /<secret>/api/v1/session` — logout.
pub async fn delete_session(state: &Arc<AppState>, req: &Request) -> Response {
    if let Some(token) = bearer_token(req) {
        if let Some(session) = state.session_for_token(&token).await {
            state.sessions.lock().await.remove(&session.id);
        }
    }
    let body = serde_json::json!({ "status": "ok" });
    let date = cryptn_front::date::httpdate_now();
    json_response(200, serde_json::to_vec(&body).unwrap(), &date)
}

/// Extract a Bearer token from `Authorization`.
fn bearer_token(req: &Request) -> Option<Vec<u8>> {
    let h = req.header("authorization")?;
    let rest = h.strip_prefix("Bearer ")?;
    cryptn_envelope::b64_decode(rest)
}
