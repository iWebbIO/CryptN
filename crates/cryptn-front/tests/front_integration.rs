//! Socket-level round-trip tests for the front: keep-alive, HEAD, 0.9,
//! 100-continue, malformed input, and error-page wiring.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use cryptn_front::parse::HeadLimits;
use cryptn_front::{serve, ConnState, Handled, Request, Response, ServerConfig};

async fn start_test_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler = Arc::new(|_conn: &ConnState, req: &Request, _s: &()| {
        let path = req.path.clone();
        let method = req.method.as_str().to_string();
        Box::pin(async move {
            let mut resp = Response::new(200)
                .header("Content-Type", "text/html; charset=UTF-8")
                .body(format!("path={path} method={method}").into_bytes());
            resp.push_header("Content-Length", resp.body.len().to_string());
            Handled::Reply(resp)
        }) as cryptn_front::BoxHandlerFut
    });

    let error_page = Arc::new(|_c: &ConnState, code: u16| {
        let body = format!("stock-error-{code}");
        let mut r = Response::new(code).body(body.into_bytes());
        r.push_header("Content-Length", r.body.len().to_string());
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

async fn raw_connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

#[tokio::test]
async fn serves_requests_with_keepalive() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"GET /index.html HTTP/1.1\r\nHost: h.test\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains("path=/index.html"), "{text}");
    assert!(text.ends_with("method=GET"), "{text}");

    // Second request on the same connection: keep-alive works.
    s.write_all(b"GET /second HTTP/1.1\r\nHost: h.test\r\n\r\n")
        .await
        .unwrap();
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("path=/second"), "{text}");
}

#[tokio::test]
async fn head_omits_body() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"HEAD /x HTTP/1.1\r\nHost: h.test\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Length: 1"));
    assert!(!text.contains("path=")); // body omitted
}

#[tokio::test]
async fn http10_without_keepalive_closes() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"GET /old HTTP/1.0\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    assert!(n > 0);
    // Connection must close: read returns 0 eventually.
    let mut tail = [0u8; 16];
    match tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut tail)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(_)) => panic!("expected close after HTTP/1.0 response"),
        Ok(Err(_)) => {}
        Err(_) => panic!("connection did not close"),
    }
}

#[tokio::test]
async fn missing_host_gets_400() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 400 Bad Request"), "{text}");
    assert!(text.contains("stock-error-400"), "{text}");
}

#[tokio::test]
async fn garbage_line_gets_400() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"\x01\x02random garbage\n\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
}

#[tokio::test]
async fn expect_100_continue_flow() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(
        b"POST /submit HTTP/1.1\r\nHost: h.test\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 1024];
    // First read: the 100 interim response.
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 100 Continue"));
    s.write_all(b"abc").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("method=POST"), "{text}");
}

#[tokio::test]
async fn http09_answers_bare_body() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"GET /legacy\r\n").await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.contains("path=/legacy"), "{text}");
    assert!(!text.contains("HTTP/1.1"), "{text}");
}

#[tokio::test]
async fn malformed_percent_escape_gets_400() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"GET /%zz HTTP/1.1\r\nHost: h\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
}

#[tokio::test]
async fn body_via_content_length() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
}

#[tokio::test]
async fn chunked_request_body() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(
        b"POST /chunky HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
}

#[tokio::test]
async fn smuggling_te_plus_cl_rejected() {
    let port = start_test_server().await;
    let mut s = raw_connect(port).await;
    s.write_all(
        b"POST /smug HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
}
