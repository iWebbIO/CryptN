//! The client-side tunnel: login, conversations, upstream POSTs and
//! downstream long-polls, wrapped in the persona app's JSON.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use cryptn_front::HttpClient;
use cryptn_record::{RecordCodec, RecordKeys};
use cryptn_tunnel::Frame;

/// Client runtime configuration.
#[derive(Clone)]
pub struct ClientConfig {
    /// host[:port] of the persona front (plain HTTP, port 80).
    pub server: String,
    /// The capability path secret.
    pub secret: String,
    /// Operator credential (base64, from the deploy bundle).
    pub credential_b64: String,
    /// Local SOCKS5 bind address.
    pub socks_bind: String,
}

/// A plain TCP stream (the local app's socket).
type TcpStreamOwned = tokio::net::TcpStream;

/// The logged-in client: token + record keys + conversations.
pub struct TunnelClient {
    cfg: ClientConfig,
    token: Vec<u8>,
    up: RecordCodec,
    down: RecordCodec,
    convs: Mutex<HashMap<[u8; 16], Arc<ConvHandle>>>,
}

/// Shared handle to a conversation.
struct ConvHandle {
    inner: Mutex<ConvInner>,
}

struct ConvInner {
    up: RecordCodec,
    down: RecordCodec,
    next_counter: u64,
    next_down_counter: u64,
    remote_closed: bool,
}

impl TunnelClient {
    /// Perform the two-step PAKE login over plain HTTP and build the client.
    pub async fn login(cfg: ClientConfig) -> Result<TunnelClient, ClientErr> {
        let credential = b64_decode_or_err(&cfg.credential_b64)?;

        // Step 1: start.
        let mut http = HttpClient::connect(&cfg.server).await?;
        let (l1, cstate) = cryptn_pake::client_login_start(&mut entropy(), &credential)
            .map_err(|_| ClientErr::Login)?;
        let body1 = serde_json::json!({
            "flow": "start",
            "login1": cryptn_envelope::b64_encode(&l1),
        });
        let body1_text = body1.to_string();
        let (code, _h, resp) = http
            .request(
                "POST",
                &format!("/{}/api/v1/session", cfg.secret),
                &request_headers(&cfg, body1_text.len()),
                Some(body1_text.as_bytes()),
            )
            .await?;
        if code != 200 {
            return Err(ClientErr::Login);
        }
        let v: serde_json::Value = serde_json::from_slice(&resp).map_err(|_| ClientErr::Login)?;
        let login2 = v
            .get("login2")
            .and_then(|s| s.as_str())
            .ok_or(ClientErr::Login)?;
        let request_id = v
            .get("request_id")
            .and_then(|s| s.as_str())
            .ok_or(ClientErr::Login)?;
        let login2_b = cryptn_envelope::b64_decode(login2).ok_or(ClientErr::Login)?;

        // Step 2: finish.
        let (l3, session_key, _export) =
            cryptn_pake::client_login_finish(cstate, &credential, &login2_b)
                .map_err(|_| ClientErr::Login)?;
        let body2 = serde_json::json!({
            "flow": "finish",
            "request_id": request_id,
            "login3": cryptn_envelope::b64_encode(&l3),
        });
        let body2_text = body2.to_string();
        let (code, _h, resp) = http
            .request(
                "POST",
                &format!("/{}/api/v1/session", cfg.secret),
                &request_headers(&cfg, body2_text.len()),
                Some(body2_text.as_bytes()),
            )
            .await?;
        if code != 200 {
            return Err(ClientErr::Login);
        }
        let v: serde_json::Value = serde_json::from_slice(&resp).map_err(|_| ClientErr::Login)?;
        let token_b64 = v
            .get("token")
            .and_then(|s| s.as_str())
            .ok_or(ClientErr::Login)?;
        let token = cryptn_envelope::b64_decode(token_b64).ok_or(ClientErr::Login)?;

        Ok(TunnelClient {
            cfg,
            token,
            up: RecordCodec::new(RecordKeys::from_session_key(
                &session_key,
                b"client-to-server",
            )),
            down: RecordCodec::new(RecordKeys::from_session_key(
                &session_key,
                b"server-to-client",
            )),
            convs: Mutex::new(HashMap::new()),
        })
    }

    /// Open a new conversation (proxied stream): send Open, spawn the engine.
    /// `local` is the accepted SOCKS socket.
    pub async fn open_conversation_raw(
        self: &Arc<Self>,
        target: cryptn_tunnel::Addr,
        early: Vec<u8>,
        local: TcpStreamOwned,
    ) -> Result<[u8; 16], ClientErr> {
        use rand::RngCore;
        let mut conv_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut conv_id);

        let frame = Frame::Open { target, early };

        let handle = Arc::new(ConvHandle {
            inner: Mutex::new(ConvInner {
                up: self.up.clone(),
                down: self.down.clone(),
                next_counter: 0,
                next_down_counter: 0,
                remote_closed: false,
            }),
        });

        // Send the Open record.
        self.send_frame(&conv_id, &handle, &frame).await?;

        // Register, then spawn the conversation engine.
        self.convs.lock().await.insert(conv_id, handle.clone());
        let client = self.clone();
        tokio::spawn(async move {
            client.run_conversation(conv_id, handle, local).await;
        });
        Ok(conv_id)
    }

    /// Send one framed record upstream as a "message".
    async fn send_frame(
        &self,
        conv_id: &[u8; 16],
        handle: &Arc<ConvHandle>,
        frame: &Frame,
    ) -> Result<(), ClientErr> {
        let (counter, sealed) = {
            let mut inner = handle.inner.lock().await;
            let counter = inner.next_counter;
            inner.next_counter += 1;
            let pt = cryptn_envelope::pad_plaintext(&frame.encode(), counter == 0);
            let assoc = assoc(conv_id, counter);
            (counter, inner.up.seal(&pt, &assoc))
        };
        let msg = cryptn_envelope::wrap_record(conv_id, counter, &sealed);
        let body = serde_json::to_vec(&msg).map_err(|_| ClientErr::Wire)?;
        let mut http = HttpClient::connect(&self.cfg.server).await?;
        let (code, _h, _b) = http
            .request(
                "POST",
                &format!("/{}/api/v1/messages", self.cfg.secret),
                &self.authed_headers(body.len()),
                Some(&body),
            )
            .await?;
        if code != 201 && code != 409 {
            return Err(ClientErr::Wire);
        }
        Ok(())
    }

    /// The per-conversation engine: local-read pump + downstream polls.
    async fn run_conversation(
        self: Arc<Self>,
        conv_id: [u8; 16],
        handle: Arc<ConvHandle>,
        mut local: TcpStreamOwned,
    ) {
        let mut up_buf = [0u8; 16384];
        loop {
            let remote_closed = {
                let inner = handle.inner.lock().await;
                inner.remote_closed
            };
            if remote_closed {
                let _ = local.shutdown().await;
                // Drain what's left from the local side, sending it up.
                loop {
                    match local.read(&mut up_buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let frame = Frame::Push {
                                data: up_buf[..n].to_vec(),
                            };
                            if self.send_frame(&conv_id, &handle, &frame).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = self.send_frame(&conv_id, &handle, &Frame::Close).await;
                self.convs.lock().await.remove(&conv_id);
                return;
            }

            // Read from the local app OR poll downstream, whichever first.
            tokio::select! {
                read = local.read(&mut up_buf) => {
                    match read {
                        Ok(0) => {
                            // Local half-closed: send Close upstream; keep
                            // polling downstream until the remote closes.
                            let _ = self.send_frame(&conv_id, &handle, &Frame::Close).await;
                        }
                        Ok(n) => {
                            let frame = Frame::Push { data: up_buf[..n].to_vec() };
                            if self.send_frame(&conv_id, &handle, &frame).await.is_err() {
                                self.convs.lock().await.remove(&conv_id);
                                return;
                            }
                        }
                        Err(_) => {
                            let _ = self.send_frame(&conv_id, &handle, &Frame::Close).await;
                            self.convs.lock().await.remove(&conv_id);
                            return;
                        }
                    }
                }
                batch = self.poll_once(&conv_id, &handle) => {
                    if let Ok(records) = batch {
                        let mut closed = false;
                        for (_counter, sealed) in records.iter() {
                            if let Some(pt) = self.open_down(&handle, &conv_id, sealed).await {
                                let pt = cryptn_envelope::strip_plaintext(&pt);
                                if let Ok(Frame::Push { data }) = Frame::decode(&pt) {
                                    if local.write_all(&data).await.is_err() {
                                        let _ = local.shutdown().await;
                                        closed = true;
                                        break;
                                    }
                                } else if let Ok(Frame::Close) = Frame::decode(&pt) {
                                    let _ = local.shutdown().await;
                                    closed = true;
                                    break;
                                }
                            }
                        }
                        if closed {
                            let _ = self.send_frame(&conv_id, &handle, &Frame::Close).await;
                            self.convs.lock().await.remove(&conv_id);
                            return;
                        }
                    }
                }
            }
        }
    }

    /// One downstream long-poll turn.
    async fn poll_once(
        &self,
        conv_id: &[u8; 16],
        handle: &Arc<ConvHandle>,
    ) -> Result<Vec<(u64, Vec<u8>)>, ClientErr> {
        let next = {
            let inner = handle.inner.lock().await;
            inner.next_down_counter.to_string()
        };
        let path = format!(
            "/{}/api/v1/conversations/{}/messages?after={}&timeout=10",
            self.cfg.secret,
            cryptn_envelope::b64url_encode(conv_id),
            next,
        );
        let mut http = HttpClient::connect(&self.cfg.server).await?;
        let (code, _h, body) = http
            .request("GET", &path, &self.authed_headers(0), None)
            .await?;
        if code == 404 {
            // Conversation unknown (e.g., server restart): treat as closed.
            let mut inner = handle.inner.lock().await;
            inner.remote_closed = true;
            return Ok(Vec::new());
        }
        if code != 200 {
            return Err(ClientErr::Wire);
        }
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| ClientErr::Wire)?;
        let messages = v
            .get("messages")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(messages.len());
        for m in messages {
            let id = m.get("id").and_then(|s| s.as_str()).unwrap_or("");
            let body = m.get("body").and_then(|s| s.as_str()).unwrap_or("");
            if let (Some(id_b), Some(sealed)) = (
                cryptn_envelope::b64url_decode(id),
                cryptn_envelope::b64_decode(body),
            ) {
                let counter = if id_b.len() == 8 {
                    u64::from_be_bytes(id_b.try_into().unwrap())
                } else {
                    0
                };
                {
                    let mut inner = handle.inner.lock().await;
                    inner.next_down_counter = counter + 1;
                }
                out.push((counter, sealed));
            }
        }
        Ok(out)
    }

    /// Open one downstream record.
    async fn open_down(
        &self,
        handle: &Arc<ConvHandle>,
        conv_id: &[u8; 16],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        let mut inner = handle.inner.lock().await;
        let counter = inner.next_down_counter.saturating_sub(1);
        let assoc = assoc(conv_id, counter);
        inner.down.open(sealed, &assoc).ok()
    }

    fn authed_headers(&self, body_len: usize) -> Vec<(String, String)> {
        let mut h = request_headers(&self.cfg, body_len);
        h.push((
            "Authorization".to_string(),
            format!("Bearer {}", cryptn_envelope::b64_encode(&self.token)),
        ));
        h
    }
}

fn assoc(conv_id: &[u8; 16], counter: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(conv_id);
    v.extend_from_slice(&counter.to_be_bytes());
    v
}

fn entropy() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

fn b64_decode_or_err(s: &str) -> Result<Vec<u8>, ClientErr> {
    cryptn_envelope::b64_decode(s).ok_or(ClientErr::Config)
}

/// Browser-shaped request headers: the persona's web app calling its API
/// over plain HTTP, exactly as a real single-page app does.
fn request_headers(cfg: &ClientConfig, body_len: usize) -> Vec<(String, String)> {
    let host = cfg
        .server
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| cfg.server.clone());
    let mut h = vec![
        ("Host".to_string(), host),
        (
            "User-Agent".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
        ),
        (
            "Accept".to_string(),
            "application/json, text/plain, */*".to_string(),
        ),
        ("Accept-Language".to_string(), "en-US,en;q=0.5".to_string()),
        ("Accept-Encoding".to_string(), "identity".to_string()),
        ("Referer".to_string(), format!("http://{}/", cfg.server)),
        ("Origin".to_string(), format!("http://{}", cfg.server)),
        ("Connection".to_string(), "keep-alive".to_string()),
    ];
    if body_len > 0 {
        h.push(("Content-Type".to_string(), "application/json".to_string()));
        h.push(("Content-Length".to_string(), body_len.to_string()));
    }
    h
}

/// Alias kept for main.rs ergonomics.
pub type SocksTargetAlias = cryptn_tunnel::Addr;

#[derive(Debug, thiserror::Error)]
pub enum ClientErr {
    #[error("config error")]
    Config,
    #[error("login failed")]
    Login,
    #[error("wire error")]
    Wire,
}

impl From<cryptn_front::ClientError> for ClientErr {
    fn from(_: cryptn_front::ClientError) -> Self {
        ClientErr::Wire
    }
}
