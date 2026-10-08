//! Shared server state: persona, credentials, tunnels, sessions.

use std::collections::HashMap;
use std::sync::Arc;

use cryptn_pake::Setup;
use cryptn_persona::PersonaConfig;
use cryptn_session::TokenAuthority;

use crate::records::SessionRecords;
use crate::tunnel_state::TunnelState;

/// A live login session (post-PAKE).
pub struct LiveSession {
    /// Session id (rides inside the bearer token).
    pub id: [u8; 16],
    /// Directional record codecs.
    pub records: SessionRecords,
    /// Token verifier for this session.
    pub tokens: TokenAuthority,
}

/// Everything the handlers share.
pub struct AppState {
    pub persona: PersonaConfig,
    /// 128-bit capability path secret (base64url chars, path-safe).
    pub capability_secret: String,
    /// OPAQUE long-term setup (deserialized at boot).
    pub setup: Setup,
    /// Registered password file (single-user deployment).
    pub server_file: Vec<u8>,
    /// Live login sessions by session id.
    pub sessions: tokio::sync::Mutex<HashMap<[u8; 16], Arc<LiveSession>>>,
    /// In-flight PAKE handshakes by random nonce (bounded, expiring).
    pub logins: tokio::sync::Mutex<HashMap<[u8; 16], PendingLogin>>,
    /// The conversation/tunnel registry.
    pub tunnels: TunnelState,
}

/// A started-but-unfinished PAKE login.
pub struct PendingLogin {
    pub state: cryptn_pake::ServerLoginState,
    pub born: std::time::Instant,
}

impl AppState {
    /// Bearer-token lookup: verify the token, find the live session.
    pub async fn session_for_token(&self, token: &[u8]) -> Option<Arc<LiveSession>> {
        // Tokens are minted per-session; try all live sessions' authorities.
        let sessions = self.sessions.lock().await;
        for (id, s) in sessions.iter() {
            if let Ok(sid) = s.tokens.verify(token) {
                if sid == *id {
                    return Some(s.clone());
                }
            }
        }
        None
    }

    /// Drop logins older than 60s (handshake garbage collection).
    pub async fn gc_logins(&self) {
        let mut logins = self.logins.lock().await;
        logins.retain(|_, p| p.born.elapsed().as_secs() < 60);
    }
}
