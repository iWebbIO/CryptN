//! The envelope layer: the persona app's JSON wire vocabulary, with size
//! shaping so record lengths draw from realistic chat-message distributions
//! instead of leaking the tunnel's true block sizes.
//!
//! Every wire-visible value is generated here — never from user data — so
//! no blocked keyword or target hostname can ever appear in a plaintext
//! field. Ciphertext rides base64 in `body`, which is exactly what an E2E
//! chat app's API looks like.

mod entropy;
mod sizes;

use base64::Engine;
use serde::{Deserialize, Serialize};

pub use sizes::{pad_plaintext, strip_plaintext};

/// A "message" as the persona app's API represents it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageOut {
    /// Conversation id (16 random bytes, base64url — looks like an id).
    pub conversation_id: String,
    /// Message id (counter-obfuscated, base64url).
    pub id: String,
    /// ISO-8601 UTC timestamp with millisecond precision, like a real API.
    pub created_at: String,
    /// The AEAD record (base64 standard).
    pub body: String,
}

/// Upstream POST body: one message.
#[derive(Debug, Serialize, Deserialize)]
pub struct PostMessage {
    #[serde(flatten)]
    pub message: MessageOut,
}

/// Downstream long-poll reply.
#[derive(Debug, Serialize)]
pub struct MessagesPage {
    pub messages: Vec<MessageOut>,
    /// Cursor the client echoes back as `?after=`.
    pub next: String,
}

/// Login request step shapes.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStart {
    /// PAKE client init (base64).
    pub login1: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFinish {
    /// PAKE client finish (base64).
    pub login3: String,
}

#[derive(Debug, Serialize)]
pub struct LoginChallenge {
    /// PAKE server response (base64).
    pub login2: String,
}

#[derive(Debug, Serialize)]
pub struct SessionCreated {
    pub token: String,
    /// Seconds until expiry, like `expires_in` in OAuth-shaped APIs.
    pub expires_in: u64,
}

/// The app's error vocabulary — deliberately identical in shape to what
/// every JSON API returns, never protocol-specific.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: &'static str,
}

pub fn error_json(msg: &'static str) -> Vec<u8> {
    serde_json::to_vec(&ApiError { error: msg }).expect("static JSON serializes")
}

/// Base64 codecs used on the wire.
pub fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

pub fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// ISO-8601 UTC "now" with millisecond precision.
pub fn iso_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, millis
    )
}

/// Civil date/time from unix seconds (Howard Hinnant's algorithm).
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32, h as u32, mi as u32, s as u32)
}

/// Build a `MessageOut` around an *already padded and sealed* record.
pub fn wrap_record(conversation_id: &[u8; 16], counter: u64, sealed_record: &[u8]) -> MessageOut {
    MessageOut {
        conversation_id: b64url_encode(conversation_id),
        id: b64url_encode(&counter.to_be_bytes()),
        created_at: iso_now(),
        body: b64_encode(sealed_record),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_base64() {
        let data = b"hello world";
        assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
        assert_eq!(b64url_decode(&b64url_encode(data)).unwrap(), data);
    }

    #[test]
    fn wrap_record_shape() {
        let cid = [9u8; 16];
        let sealed = b"ciphertext-bytes";
        let m = wrap_record(&cid, 7, sealed);
        assert_eq!(m.conversation_id.len(), 22); // 16 bytes b64url nopad
        assert_eq!(m.id.len(), 11); // 8 bytes b64url nopad
        assert!(m.created_at.ends_with('Z'));
        assert!(m.created_at.contains('T'));
        assert_eq!(b64_decode(&m.body).unwrap(), sealed);
    }

    #[test]
    fn error_json_is_generic() {
        assert_eq!(
            error_json("invalid email or password"),
            br#"{"error":"invalid email or password"}"#
        );
    }

    #[test]
    fn iso_now_format() {
        let s = iso_now();
        assert!(s.len() == 24, "{s}"); // YYYY-MM-DDTHH:MM:SS.mmmZ
    }
}
