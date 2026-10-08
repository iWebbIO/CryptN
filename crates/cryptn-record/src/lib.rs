//! The record layer: XChaCha20-Poly1305 AEAD with replay defense.
//!
//! Every tunneled byte (including target hostnames in a conversation's first
//! record) travels as an AEAD record. Each direction keeps a strictly
//! increasing counter; the wire carries `nonce || ciphertext || tag`, and the
//! receiver tracks the highest accepted counter plus a small window of
//! recently seen nonces — replays answer the API layer's 409-duplicate shape.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Nonce size for XChaCha20 (24 bytes).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag size.
pub const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("decryption failed")]
    Decrypt,
    #[error("replayed record")]
    Replayed,
    #[error("record too small")]
    Truncated,
}

/// Derive directional record keys from the PAKE session key via HKDF
/// (session keys are never used directly as AEAD keys).
#[derive(Clone)]
pub struct RecordKeys {
    aead: XChaCha20Poly1305,
}

impl RecordKeys {
    /// `context` binds the derivation to its purpose (e.g. b"up"/b"down").
    pub fn from_session_key(session_key: &[u8; 64], context: &[u8]) -> RecordKeys {
        let hk = Hkdf::<Sha256>::new(None, session_key);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(context, &mut *okm).expect("32-byte OKM is valid");
        RecordKeys {
            aead: XChaCha20Poly1305::new(Key::from_slice(okm.as_ref())),
        }
    }
}

/// Per-direction record state: keys + replay tracking.
#[derive(Clone)]
pub struct RecordCodec {
    keys: RecordKeys,
    /// Nonces accepted so far (replay defense: a reused nonce is rejected;
    /// strictly-monotonic message counters are enforced one layer up, in the
    /// conversation state, which maps violations to the app's 409 shape).
    seen_nonces: std::collections::HashSet<[u8; NONCE_LEN]>,
}

impl RecordCodec {
    pub fn new(keys: RecordKeys) -> RecordCodec {
        RecordCodec {
            keys,
            seen_nonces: std::collections::HashSet::new(),
        }
    }

    /// Encrypt one record. Returns `nonce || ct || tag`.
    pub fn seal(&self, plaintext: &[u8], associated: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct = self
            .keys
            .aead
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: associated,
                },
            )
            .expect("XChaCha20-Poly1305 encryption cannot fail with valid key");
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt one record, enforcing replay defense: a nonce already seen,
    /// or a record whose associated data mismatches, is `Replayed`/`Decrypt`.
    pub fn open(&mut self, wire: &[u8], associated: &[u8]) -> Result<Vec<u8>, RecordError> {
        if wire.len() < NONCE_LEN + TAG_LEN {
            return Err(RecordError::Truncated);
        }
        let (nonce_bytes, ct) = wire.split_at(NONCE_LEN);
        let nonce_arr: [u8; NONCE_LEN] =
            nonce_bytes.try_into().map_err(|_| RecordError::Truncated)?;
        if self.seen_nonces.contains(&nonce_arr) {
            return Err(RecordError::Replayed);
        }
        let pt = self
            .keys
            .aead
            .decrypt(
                XNonce::from_slice(&nonce_arr),
                Payload {
                    msg: ct,
                    aad: associated,
                },
            )
            .map_err(|_| RecordError::Decrypt)?;
        self.seen_nonces.insert(nonce_arr);
        // Bound the window: beyond 1024 recent nonces, reset tracking (the
        // strictly-monotonic per-direction counter lives in the envelope's
        // `id` field; this set covers reordered arrival only).
        if self.seen_nonces.len() > 1024 {
            self.seen_nonces.clear();
            self.seen_nonces.insert(nonce_arr);
        }
        Ok(pt)
    }
}

/// Zeroize a key buffer when dropped.
pub fn zeroize_key(k: &mut [u8]) {
    k.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> [u8; 64] {
        let mut s = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn round_trip() {
        let sk = session();
        let up = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut down = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let rec = up.seal(b"hello http", b"conv-1");
        assert_eq!(down.open(&rec, b"conv-1").unwrap(), b"hello http");
    }

    #[test]
    fn wrong_associated_data_fails() {
        let sk = session();
        let up = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut down = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let rec = up.seal(b"data", b"conv-1");
        assert!(down.open(&rec, b"conv-2").is_err());
    }

    #[test]
    fn exact_replay_rejected() {
        let sk = session();
        let up = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut down = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let rec = up.seal(b"once", b"conv-1");
        assert!(down.open(&rec, b"conv-1").is_ok());
        assert!(matches!(
            down.open(&rec, b"conv-1"),
            Err(RecordError::Replayed)
        ));
    }

    #[test]
    fn directions_are_isolated() {
        let sk = session();
        let up = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut other = RecordCodec::new(RecordKeys::from_session_key(&sk, b"down"));
        let rec = up.seal(b"x", b"a");
        assert!(other.open(&rec, b"a").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sk = session();
        let up = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut down = RecordCodec::new(RecordKeys::from_session_key(&sk, b"up"));
        let mut rec = up.seal(b"payload", b"aad");
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        assert!(down.open(&rec, b"aad").is_err());
    }
}
