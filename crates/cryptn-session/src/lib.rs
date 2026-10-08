//! Session tokens: opaque AEAD-encrypted blobs carrying an expiry, minted
//! by the server after a successful PAKE login and presented by the client
//! as `Authorization: Bearer <token>` — the most boring auth header alive.
//!
//! The token key is derived from the PAKE session key, so tokens from one
//! login cannot be forged or read in another; expiry makes a stolen token
//! die quietly; and an expired token answers the persona's
//! `401 {"error":"session expired"}` exactly like a real app.

mod derive;
mod entropy;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

const NONCE_LEN: usize = 24;
const TOKEN_AAD: &[u8] = b"cryptn-session-token";

/// Errors from token verification.
#[derive(Debug)]
pub enum TokenError {
    /// Token could not be decoded or decrypted.
    Invalid,
    /// Token decrypted but its expiry has passed.
    Expired,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TokenError::Invalid => "token could not be decoded",
            TokenError::Expired => "token expired",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TokenError {}

/// Token minting/verification for one deployment.
pub struct TokenAuthority {
    aead: XChaCha20Poly1305,
}

impl TokenAuthority {
    /// Derive from the PAKE session key (server side keeps it in memory).
    pub fn from_session_key(session_key: &[u8; 64]) -> TokenAuthority {
        let key_bytes = derive::derive_aead_key(session_key);
        TokenAuthority {
            aead: XChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref())),
        }
    }

    /// Mint a token for `session_id`, valid for `ttl_secs`.
    /// Wire form: `nonce(24) || ct(expiry(8) || session_id(16)) || tag(16)`.
    pub fn mint(&self, session_id: [u8; 16], ttl_secs: u64) -> Vec<u8> {
        let expiry = unix_now() + ttl_secs;
        let mut pt = Vec::with_capacity(24);
        pt.extend_from_slice(&expiry.to_be_bytes());
        pt.extend_from_slice(&session_id);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        entropy::random_bytes(&mut nonce_bytes);
        let ct = self
            .aead
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &pt,
                    aad: TOKEN_AAD,
                },
            )
            .expect("AEAD encrypt cannot fail with a valid key");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Verify a token: returns the session id, or `Expired`/`Invalid`.
    pub fn verify(&self, wire: &[u8]) -> Result<[u8; 16], TokenError> {
        if wire.len() < NONCE_LEN + 8 + 16 + 16 {
            return Err(TokenError::Invalid);
        }
        let (nonce_bytes, ct) = wire.split_at(NONCE_LEN);
        let pt = self
            .aead
            .decrypt(
                XNonce::from_slice(nonce_bytes),
                Payload {
                    msg: ct,
                    aad: TOKEN_AAD,
                },
            )
            .map_err(|_| TokenError::Invalid)?;
        if pt.len() != 8 + 16 {
            return Err(TokenError::Invalid);
        }
        let expiry = u64::from_be_bytes(pt[..8].try_into().expect("8 bytes"));
        if unix_now() > expiry {
            return Err(TokenError::Expired);
        }
        Ok(pt[8..].try_into().expect("16 bytes"))
    }
}

/// Current unix time in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk() -> [u8; 64] {
        let mut s = [0u8; 64];
        entropy::random_bytes(&mut s);
        s
    }

    #[test]
    fn mint_and_verify_round_trip() {
        let auth = TokenAuthority::from_session_key(&sk());
        let sid = [7u8; 16];
        let tok = auth.mint(sid, 3600);
        assert_eq!(auth.verify(&tok).unwrap(), sid);
    }

    #[test]
    fn expired_token_rejected() {
        let auth = TokenAuthority::from_session_key(&sk());
        let tok = auth.mint([1u8; 16], 0);
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(matches!(auth.verify(&tok), Err(TokenError::Expired)));
    }

    #[test]
    fn foreign_authority_rejects() {
        let a = TokenAuthority::from_session_key(&sk());
        let b = TokenAuthority::from_session_key(&sk());
        let tok = a.mint([2u8; 16], 3600);
        assert!(matches!(b.verify(&tok), Err(TokenError::Invalid)));
    }

    #[test]
    fn garbage_rejected() {
        let auth = TokenAuthority::from_session_key(&sk());
        assert!(matches!(auth.verify(b"nonsense"), Err(TokenError::Invalid)));
        assert!(matches!(auth.verify(&[]), Err(TokenError::Invalid)));
    }
}
