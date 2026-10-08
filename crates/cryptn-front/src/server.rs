//! The connection loop: accept, parse, dispatch, keep-alive, error pages.
//!
//! Semantics mirror Apache's MPM behavior: HTTP/1.1 keeps alive by default
//! (bounded by MaxKeepAliveRequests=100), HTTP/1.0 only when `Connection:
//! keep-alive` was sent, 0.9 answers with a bare body and hangs up, request
//! errors emit the persona's error page and close, and `Expect: 100-continue`
//! gets the interim response before the body is read.
//!
//! Handlers are async futures: a long-poll endpoint simply awaits inside the
//! handler before returning its `Reply` — the connection stays parked in the
//! handler with no separate ownership dance.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::parse::{read_body, read_head, HeadLimits, HeadReader};
use crate::response::Response;
use crate::{Method, Request, Version};

/// Boxed async future. `'static`: handlers clone what they need before
/// awaiting (long-polls park on `Arc` state, not borrowed requests).
pub type BoxHandlerFut = Pin<Box<dyn Future<Output = Handled> + Send>>;

/// What a handler does with a parsed request.
#[derive(Debug)]
pub enum Handled {
    /// A complete response; keep-alive decisions follow the request.
    Reply(Response),
    /// Respond and close the connection afterwards regardless.
    ReplyAndClose(Response),
}

/// Per-connection context the front exposes to persona/handler code.
pub struct ConnState {
    /// Remote peer address.
    pub peer: std::net::SocketAddr,
    /// Server-side listen address.
    pub local: std::net::SocketAddr,
}

pub type Handler<S> = Arc<dyn Fn(&ConnState, &Request, &S) -> BoxHandlerFut + Send + Sync>;

/// Status → persona error page (stock 400/404/403/… pages live in the persona).
pub type ErrorPage = Arc<dyn Fn(&ConnState, u16) -> Response + Send + Sync>;

pub struct ServerConfig<S> {
    pub limits: HeadLimits,
    /// `MaxKeepAliveRequests` (Apache default 100).
    pub max_keepalive_requests: usize,
    pub handler: Handler<S>,
    pub error_page: ErrorPage,
    pub state: S,
}

pub async fn serve<S: Send + Sync + 'static>(
    listener: TcpListener,
    config: Arc<ServerConfig<S>>,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        tokio::spawn(async move {
            let local = stream.local_addr().unwrap_or(peer);
            let state = ConnState { peer, local };
            handle_connection(stream, state, config).await;
        });
    }
}

async fn handle_connection<S: Send + Sync + 'static>(
    stream: TcpStream,
    conn: ConnState,
    config: Arc<ServerConfig<S>>,
) {
    // TCP_NODELAY, like a real webserver's accepted sockets.
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = HeadReader::new(read_half);

    for _ in 0..config.max_keepalive_requests {
        let head = match read_head(&mut reader, &config.limits).await {
            Ok(h) => h,
            Err(e) => {
                let status = e.status().unwrap_or(400);
                let resp = (config.error_page)(&conn, status);
                let _ = write_half.write_all(&resp.serialize(false, false)).await;
                return;
            }
        };

        // Expect: 100-continue — interim response before the body is read.
        if head.version == Version::Http11
            && head
                .header("expect")
                .map(|v| v.eq_ignore_ascii_case("100-continue"))
                .unwrap_or(false)
        {
            reader.send_continue(&mut write_half).await;
        }

        let request = match read_body(&mut reader, head, &config.limits).await {
            Ok(r) => r,
            Err(e) => {
                let status = e.status().unwrap_or(400);
                let resp = (config.error_page)(&conn, status);
                let _ = write_half.write_all(&resp.serialize(false, false)).await;
                return;
            }
        };

        let handled = ((config.handler)(&conn, &request, &config.state)).await;

        match handled {
            Handled::ReplyAndClose(resp) => {
                let _ = write_half.write_all(&resp.serialize(false, false)).await;
                let _ = write_half.shutdown().await;
                return;
            }
            Handled::Reply(resp) => {
                let is_head = request.method == Method::Head;
                let http09 = request.version == Version::Http09;
                let keep = should_keep_alive(&request);
                let bytes = resp.serialize(http09, is_head);
                if write_half.write_all(&bytes).await.is_err() {
                    return;
                }
                if http09 {
                    return; // 0.9: answer body and close
                }
                if !keep {
                    let _ = write_half.shutdown().await;
                    return;
                }
            }
        }
    }
    // MaxKeepAliveRequests reached: the persona composes `Connection: close`
    // on the last response; we simply stop reading further requests.
}

fn should_keep_alive(req: &Request) -> bool {
    let wants_close = |values: &[&str]| {
        values
            .iter()
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("close"))
    };
    let wants_keep = |values: &[&str]| {
        values
            .iter()
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("keep-alive"))
    };
    match req.version {
        Version::Http11 => !wants_close(&req.header_values("connection")),
        Version::Http10 => wants_keep(&req.header_values("connection")),
        Version::Http09 => false,
    }
}
