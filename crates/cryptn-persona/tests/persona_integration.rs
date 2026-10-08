//! Socket-level persona tests: the exact bytes a scanner or browser sees.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use cryptn_front::parse::HeadLimits;
use cryptn_front::{serve, ConnState, Handled, Request, Response, ServerConfig};
use cryptn_persona::{persona_handle, PersonaConfig};

/// Serve the persona on an ephemeral port; returns the port.
/// Capability path is disabled here (persona-only view, exactly what an
/// outside scanner sees).
async fn start_persona() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler = Arc::new(|_conn: &ConnState, req: &Request, _s: &()| {
        let date = cryptn_front::date::httpdate_now();
        let resp = persona_handle(req, &PersonaConfig::default(), &date);
        Box::pin(async move { Handled::Reply(resp) }) as cryptn_front::BoxHandlerFut
    });

    let error_page = Arc::new(|_c: &ConnState, code: u16| {
        let body = cryptn_persona::error_pages::error_page(
            408.min(code),
            "GET",
            "Apache/2.4.58 (Ubuntu)",
            "127.0.0.1",
            80,
        );
        let mut r = Response::new(code);
        r.push_header("Content-Length", body.len().to_string());
        r.push_header("Content-Type", "text/html; charset=iso-8859-1");
        r.body = body;
        r
    });

    let config = Arc::new(ServerConfig {
        limits: HeadLimits::default(),
        max_keepalive_requests: 100,
        handler,
        error_page,
        state: (),
    });

    tokio::spawn(async move {
        let _ = serve(listener, config).await;
    });
    port
}

async fn get(port: u16, raw: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let n = s.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn default_page_is_served_at_root() {
    let port = start_persona().await;
    let text = get(port, "GET / HTTP/1.1\r\nHost: box.example\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(
        text.contains("Server: Apache/2.4.58 (Ubuntu)\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Content-Type: text/html; charset=UTF-8"),
        "{text}"
    );
    assert!(
        text.contains("Apache2 Ubuntu Default Page: It works"),
        "{text}"
    );
    assert!(text.contains("<!DOCTYPE html PUBLIC"), "{text}");
    assert!(text.contains("Content-Length: 10672"), "{text}");
    // Header order: Server comes before Last-Modified.
    let server_at = text.find("Server:").unwrap();
    let lm_at = text.find("Last-Modified:").unwrap();
    assert!(server_at < lm_at);
    assert!(text.contains("ETag: \"29cd-"), "{text}");
    assert!(text.contains("Accept-Ranges: bytes"), "{text}");
    assert!(text.contains("Keep-Alive: timeout=5, max=100"), "{text}");
}

#[tokio::test]
async fn unknown_path_is_stock_404() {
    let port = start_persona().await;
    let text = get(
        port,
        "GET /wp-admin/setup-config.php HTTP/1.1\r\nHost: box.example\r\n\r\n",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text}");
    assert!(text.contains("<title>404 Not Found</title>"), "{text}");
    assert!(text.contains("<h1>Not Found</h1>"), "{text}");
    assert!(
        text.contains("<p>The requested URL was not found on this server.</p>"),
        "{text}"
    );
    assert!(
        text.contains("<address>Apache/2.4.58 (Ubuntu) Server at box.example Port 80</address>"),
        "{text}"
    );
    assert!(text.contains("charset=iso-8859-1"), "{text}");
}

#[tokio::test]
async fn server_status_is_404() {
    let port = start_persona().await;
    let text = get(
        port,
        "GET /server-status HTTP/1.1\r\nHost: box.example\r\n\r\n",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
}

#[tokio::test]
async fn conditional_get_304() {
    let port = start_persona().await;
    let first = get(port, "GET / HTTP/1.1\r\nHost: b\r\n\r\n").await;
    let etag = first
        .lines()
        .find(|l| l.starts_with("ETag:"))
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .to_string();
    let ask = format!("GET / HTTP/1.1\r\nHost: b\r\nIf-None-Match: {etag}\r\n\r\n");
    let text = get(port, &ask).await;
    assert!(text.starts_with("HTTP/1.1 304 Not Modified\r\n"), "{text}");
    assert!(!text.contains("<!DOCTYPE"), "{text}");
}

#[tokio::test]
async fn range_request_206() {
    let port = start_persona().await;
    let text = get(
        port,
        "GET / HTTP/1.1\r\nHost: b\r\nRange: bytes=0-99\r\n\r\n",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{text}"
    );
    assert!(text.contains("Content-Range: bytes 0-99/10672"), "{text}");
    assert!(text.contains("Content-Length: 100"), "{text}");
}

#[tokio::test]
async fn range_unsatisfiable_416() {
    let port = start_persona().await;
    let text = get(
        port,
        "GET / HTTP/1.1\r\nHost: b\r\nRange: bytes=99999999-\r\n\r\n",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 416"), "{text}");
    assert!(text.contains("Content-Range: bytes */10672"), "{text}");
}

#[tokio::test]
async fn method_not_allowed_with_allow() {
    let port = start_persona().await;
    let text = get(
        port,
        "PUT /index.html HTTP/1.1\r\nHost: b\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Allow: GET,HEAD,POST,OPTIONS,TRACE"),
        "{text}"
    );
    assert!(
        text.contains("The requested method PUT is not allowed"),
        "{text}"
    );
}

#[tokio::test]
async fn options_gets_allow_list() {
    let port = start_persona().await;
    let text = get(port, "OPTIONS / HTTP/1.1\r\nHost: b\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(
        text.contains("Allow: GET,HEAD,POST,OPTIONS,TRACE"),
        "{text}"
    );
    assert!(text.contains("Content-Length: 0"), "{text}");
}

#[tokio::test]
async fn trace_echoes_request() {
    let port = start_persona().await;
    let text = get(port, "TRACE / HTTP/1.1\r\nHost: b\r\nX-Probe: 1\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains("Content-Type: message/http"), "{text}");
    assert!(text.contains("TRACE / HTTP/1.1"), "{text}");
    assert!(text.contains("X-Probe: 1"), "{text}");
}

#[tokio::test]
async fn unknown_method_is_501() {
    let port = start_persona().await;
    let text = get(port, "PROPFIND / HTTP/1.1\r\nHost: b\r\n\r\n").await;
    assert!(
        text.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{text}"
    );
    assert!(
        text.contains("PROPFIND not supported for current URL"),
        "{text}"
    );
}

#[tokio::test]
async fn icons_serves_logo() {
    let port = start_persona().await;
    let text = get(
        port,
        "GET /icons/ubuntu-logo.png HTTP/1.1\r\nHost: b\r\n\r\n",
    )
    .await;
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains("Content-Type: image/png"), "{text}");
    // The embedded asset is 7427 bytes; verify via header (binary body is
    // lossy-converted in this test, so length is the reliable check).
    assert!(text.contains("Content-Length: 7427"), "{text}");
}

#[tokio::test]
async fn icons_other_is_404() {
    let port = start_persona().await;
    let text = get(port, "GET /icons/unknown.gif HTTP/1.1\r\nHost: b\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
}

#[tokio::test]
async fn http10_gets_close() {
    let port = start_persona().await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 65536];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    // HTTP/1.0 without keep-alive: server closes (read returns 0).
    let n2 = s.read(&mut buf).await.unwrap();
    assert_eq!(n2, 0, "expected connection close for HTTP/1.0");
}

#[tokio::test]
async fn directory_traversal_is_404() {
    let port = start_persona().await;
    let text = get(port, "GET /../../etc/passwd HTTP/1.1\r\nHost: b\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 404"), "{text}");
}

#[tokio::test]
async fn index_html_alias_works() {
    let port = start_persona().await;
    let text = get(port, "GET /index.html HTTP/1.1\r\nHost: b\r\n\r\n").await;
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
}
