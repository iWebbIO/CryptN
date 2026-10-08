//! Server-side tunnel state: conversations, long-poll delivery, egress.
//!
//! One conversation = one proxied stream. Upstream records arrive via
//! `POST /messages` (the client's "sent messages"); downstream records are
//! drained by long-polls (`GET /conversations/{id}/messages`). The HTTP
//! shape is a chat app's; everything tunnel-ish lives inside the AEAD
//! records the envelope wraps.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use cryptn_egress::EgressGuard;
use cryptn_tunnel::{Addr, Frame};

use crate::records::{record_assoc, SessionRecords};

/// Server-side conversation state.
struct Conversation {
    /// Upstream codec (client→server).
    up: cryptn_record::RecordCodec,
    /// Downstream codec (server→client).
    down: cryptn_record::RecordCodec,
    /// Next upstream counter the client must use (strict monotonicity).
    next_client_counter: u64,
    /// Next downstream record counter we will emit.
    down_counter: u64,
    /// Sealed records queued for the client's next long-poll.
    outbox: Vec<(u64, Vec<u8>)>,
    /// The dialed target stream, while open.
    stream: Option<tokio::net::TcpStream>,
    /// Target stream reached EOF or errored (Close record pending emission).
    target_done: bool,
    /// Close record already emitted to the client.
    outbox_is_terminal: bool,
}

impl Conversation {
    fn new(records: &SessionRecords) -> Conversation {
        Conversation {
            up: records.up_codec(),
            down: records.down_codec(),
            next_client_counter: 0,
            down_counter: 0,
            outbox: Vec::new(),
            stream: None,
            target_done: false,
            outbox_is_terminal: false,
        }
    }
}

/// All live conversations for the deployment.
pub struct TunnelState {
    guard: EgressGuard,
    convs: Mutex<HashMap<[u8; 16], Arc<Mutex<Conversation>>>>,
}

/// What happened to an accepted upstream message.
#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamOutcome {
    Opened,
    Pushed,
    Closed,
    Acked,
    /// Replayed/reordered counter or repeated open — the app's 409 shape.
    Duplicate,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("bad record")]
    BadRecord,
    #[error("bad frame")]
    BadFrame,
    #[error("push before open")]
    NotOpen,
    #[error("dial failed")]
    DialFailed,
    #[error("io error")]
    Io,
}

impl TunnelState {
    pub fn new(guard: EgressGuard) -> TunnelState {
        TunnelState {
            guard,
            convs: Mutex::new(HashMap::new()),
        }
    }

    async fn get_or_create(
        &self,
        records: &SessionRecords,
        conv_id: &[u8; 16],
    ) -> Arc<Mutex<Conversation>> {
        let mut convs = self.convs.lock().await;
        if let Some(existing) = convs.get(conv_id) {
            return existing.clone();
        }
        let conv = Arc::new(Mutex::new(Conversation::new(records)));
        convs.insert(*conv_id, conv.clone());
        conv
    }

    /// Process one upstream sealed record.
    pub async fn handle_upstream(
        &self,
        records: &SessionRecords,
        conv_id: &[u8; 16],
        counter: u64,
        sealed_record: &[u8],
    ) -> Result<UpstreamOutcome, TunnelError> {
        let conv = self.get_or_create(records, conv_id).await;
        let mut c = conv.lock().await;

        // Strictly increasing counters: replays/reorders → Duplicate (409).
        if counter < c.next_client_counter {
            return Ok(UpstreamOutcome::Duplicate);
        }
        c.next_client_counter = counter + 1;

        let pt =
            c.up.open(sealed_record, &record_assoc(conv_id, counter))
                .map_err(|_| TunnelError::BadRecord)?;
        let pt = cryptn_envelope::strip_plaintext(&pt);
        let frame = Frame::decode(&pt).map_err(|_| TunnelError::BadFrame)?;

        match frame {
            Frame::Open { target, early } => {
                if c.stream.is_some() {
                    return Ok(UpstreamOutcome::Duplicate);
                }
                let (host, port) = match &target {
                    Addr::Domain(h, p) => (h.clone(), *p),
                    Addr::Ip(ip, p) => (ip.to_string(), *p),
                };
                let stream = self.guard.dial(&host, port).await.map_err(|_| {
                    // Queue a Close so the client's stream ends promptly.
                    TunnelError::DialFailed
                })?;
                if !early.is_empty() {
                    let mut w = stream;
                    if w.write_all(&early).await.is_err() {
                        return Err(TunnelError::Io);
                    }
                    c.stream = Some(w);
                } else {
                    c.stream = Some(stream);
                }
                Ok(UpstreamOutcome::Opened)
            }
            Frame::Push { data } => {
                let mut stream = c.stream.take().ok_or(TunnelError::NotOpen)?;
                let ok = stream.write_all(&data).await.is_ok();
                c.stream = Some(stream);
                if !ok {
                    return Err(TunnelError::Io);
                }
                Ok(UpstreamOutcome::Pushed)
            }
            Frame::Close => {
                if let Some(mut s) = c.stream.take() {
                    let _ = s.shutdown().await;
                }
                Ok(UpstreamOutcome::Closed)
            }
            Frame::Ack => Ok(UpstreamOutcome::Acked),
        }
    }

    /// Long-poll: pump the target stream, queue sealed downstream records,
    /// and return the batch (possibly empty, like a chat app with no news).
    /// Also performs a single pump-and-close on `handle_upstream` paths —
    /// callers invoke this from their long-poll GET only.
    pub async fn poll_downstream(
        &self,
        records: &SessionRecords,
        conv_id: &[u8; 16],
        timeout_ms: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, TunnelError> {
        let conv = self.get_or_create(records, conv_id).await;
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.min(25_000));

        loop {
            let batch = {
                let mut c = conv.lock().await;
                // One non-blocking pump of the target stream.
                if let Some(mut stream) = c.stream.take() {
                    let mut buf = [0u8; 16384];
                    match stream.try_read(&mut buf) {
                        Ok(0) => {
                            c.target_done = true;
                            let _ = stream.shutdown().await;
                        }
                        Ok(n) => {
                            let frame = Frame::Push {
                                data: buf[..n].to_vec(),
                            };
                            seal_down(&mut c, &frame.encode(), conv_id);
                            c.stream = Some(stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            c.stream = Some(stream);
                        }
                        Err(_) => {
                            c.target_done = true;
                            let _ = stream.shutdown().await;
                        }
                    }
                }
                if c.target_done {
                    // Emit Close once; remember it was emitted.
                    seal_down(&mut c, &Frame::Close.encode(), conv_id);
                    c.target_done = false;
                    c.outbox_is_terminal = true;
                }
                let out: Vec<(u64, Vec<u8>)> = std::mem::take(&mut c.outbox);
                out
            };
            if !batch.is_empty() {
                return Ok(batch);
            }
            // Terminal state with nothing queued: an empty page (the client
            // learns of the close from the Close record already delivered).
            let wait = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(std::time::Duration::from_millis(250));
            if wait.is_zero() {
                return Ok(Vec::new());
            }
            tokio::time::sleep(wait).await;
        }
    }
}

/// Seal a downstream frame into a conversation's outbox.
fn seal_down(c: &mut Conversation, frame_bytes: &[u8], conv_id: &[u8; 16]) {
    let counter = c.down_counter;
    c.down_counter += 1;
    let padded = cryptn_envelope::pad_plaintext(frame_bytes, counter == 0);
    let sealed = c.down.seal(&padded, &record_assoc(conv_id, counter));
    c.outbox.push((counter, sealed));
}
