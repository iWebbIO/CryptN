//! Session-bound record codecs: the up/down direction pair a login holds.

use cryptn_record::{RecordCodec, RecordKeys};

/// Both directional codecs for one login session.
pub struct SessionRecords {
    pub up: RecordCodec,
    pub down: RecordCodec,
}

impl SessionRecords {
    /// Derive both directions from the PAKE session key.
    pub fn from_session_key(session_key: &[u8; 64]) -> SessionRecords {
        SessionRecords {
            up: RecordCodec::new(RecordKeys::from_session_key(
                session_key,
                b"client-to-server",
            )),
            down: RecordCodec::new(RecordKeys::from_session_key(
                session_key,
                b"server-to-client",
            )),
        }
    }

    /// Clone the directional codecs for a conversation.
    pub fn up_codec(&self) -> RecordCodec {
        self.up.clone()
    }

    pub fn down_codec(&self) -> RecordCodec {
        self.down.clone()
    }
}

/// Associated data binding a record to its conversation and counter.
pub fn record_assoc(conv_id: &[u8; 16], counter: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(conv_id);
    v.extend_from_slice(&counter.to_be_bytes());
    v
}
