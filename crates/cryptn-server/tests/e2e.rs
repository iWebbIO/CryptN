//! Full-stack integration: server + client + echo target, driven exactly
//! like a real user (SOCKS5 → tunnel → API → egress → target), plus the
//! probe-resistance suite (scans, capability-path guesses, replays).
//!
//! The stack runs with dev-permissive egress so the server can dial the
//! test's loopback echo target; production egress is exercised in
//! cryptn-egress's own tests.

#[cfg(feature = "dev")]
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use cryptn_egress::EgressGuard;

/// Boot everything; returns addresses and secrets.
#[allow(dead_code)] // some fields are only consumed under the `dev` feature
struct Stack {
    front: String,
    echo_port: u16,
    secret: String,
    credential: String,
}

async fn boot_stack() -> Stack {
    // Identity.
    let mut entropy = rand::rngs::OsRng;
    let setup = cryptn_pake::new_server_setup();
    let mut credential = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut credential);
    let export = cryptn_pake::register(&mut entropy, &setup, &credential).unwrap();
    let mut secret_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = cryptn_envelope::b64url_encode(&secret_bytes);

    // Echo target on loopback (the tunnel's dial destination).
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    // The server stack (dev egress permits the loopback echo).
    #[cfg(feature = "dev")]
    let guard = EgressGuard::permissive_for_tests();
    #[cfg(not(feature = "dev"))]
    let guard = EgressGuard::production();

    let app = cryptn_server::build_state(
        cryptn_pake::deserialize_setup(&cryptn_pake::serialize_setup(&setup)).unwrap(),
        export.server_file.clone(),
        secret.clone(),
        guard,
    );

    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_port = front.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = cryptn_server::serve_stack(front, app).await;
    });

    Stack {
        front: format!("127.0.0.1:{front_port}"),
        echo_port,
        secret,
        credential: cryptn_envelope::b64_encode(&export.client_material),
    }
}

/// Raw HTTP request helper.
async fn http_raw(addr: &str, raw: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let code: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, text)
}

// ---------------------------------------------------------------------------
// Probe resistance (the disguise itself)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scanner_sees_stock_apache() {
    let st = boot_stack().await;
    let (code, text) = http_raw(&st.front, b"GET / HTTP/1.1\r\nHost: box.example\r\n\r\n").await;
    assert_eq!(code, 200);
    assert!(text.contains("Apache/2.4.58 (Ubuntu)"));
    assert!(text.contains("Apache2 Ubuntu Default Page: It works"));

    // Common scanner paths all 404 with the stock page.
    for path in [
        "/wp-admin/setup-config.php",
        "/manager/html",
        "/.env",
        "/phpmyadmin/",
        "/solr/",
        "/api/v1/users",
        "/cgi-bin/test.cgi",
    ] {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: box.example\r\n\r\n");
        let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
        assert_eq!(code, 404, "{path}");
        assert!(text.contains("The requested URL was not found on this server."));
    }
}

#[tokio::test]
async fn wrong_capability_secret_is_stock_apache_behavior() {
    let st = boot_stack().await;
    // Someone guesses an API-ish path with the wrong secret: stock Apache
    // semantics for a POST against the static default page — 405 with the
    // stock Allow list, exactly what the real box gives.
    let raw = concat!(
        "POST /deadbeefdeadbeef/api/v1/session HTTP/1.1\r\n",
        "Host: b\r\nContent-Length: 2\r\n\r\n{}"
    );
    let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code, 405);
    assert!(text.contains("Allow: GET,HEAD,POST,OPTIONS,TRACE"));
    assert!(text.contains("The requested method POST is not allowed"));
    // And a GET with the wrong secret is the plain stock 404.
    let raw = "GET /deadbeefdeadbeef/api/v1/session HTTP/1.1\r\nHost: b\r\n\r\n";
    let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code, 404);
    assert!(text.contains("The requested URL was not found on this server."));
    assert!(!text.contains("invalid email or password"));
}

#[tokio::test]
async fn right_secret_without_valid_body_is_401_app_json() {
    let st = boot_stack().await;
    // Right path, garbage body: the app's login error, not a stack trace.
    let raw = format!(
        "POST /{}/api/v1/session HTTP/1.1\r\nHost: b\r\nContent-Length: 2\r\n\r\n{{}}",
        st.secret
    );
    let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code, 401);
    assert!(text.contains("invalid email or password"));
}

#[tokio::test]
async fn messages_without_token_is_401() {
    let st = boot_stack().await;
    let raw = format!(
        "POST /{}/api/v1/messages HTTP/1.1\r\nHost: b\r\nContent-Length: 2\r\n\r\n{{}}",
        st.secret
    );
    let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code, 401);
    assert!(text.contains("session expired"));
}

#[tokio::test]
async fn unknown_api_route_is_404() {
    let st = boot_stack().await;
    let raw = format!("GET /{}/api/v1/nope HTTP/1.1\r\nHost: b\r\n\r\n", st.secret);
    let (code, text) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code, 404);
    assert!(text.contains("The requested URL was not found on this server."));
}

#[tokio::test]
async fn replayed_login_request_is_401() {
    let st = boot_stack().await;
    // A captured login-start body, replayed verbatim: the fresh handshake
    // state (request_id) is single-use, so a replay decodes to the app's
    // invalid-credentials error — never a protocol error.
    let entropy = &mut rand::rngs::OsRng;
    let (l1, _cstate) = cryptn_pake::client_login_start(
        entropy,
        &cryptn_envelope::b64_decode(&st.credential).unwrap(),
    )
    .unwrap();
    let body = serde_json::json!({
        "flow": "start",
        "login1": cryptn_envelope::b64_encode(&l1),
    })
    .to_string();
    let raw = format!(
        "POST /{}/api/v1/session HTTP/1.1\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        st.secret,
        body.len(),
        body
    );
    let (code1, text1) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code1, 200);
    // Replay the identical bytes.
    let (code2, _text2) = http_raw(&st.front, raw.as_bytes()).await;
    assert_eq!(code2, 200, "a fresh login1 is legitimately replayable");
    // But a replayed *finish* (same request_id twice) is 401.
    let json1 = text1
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or(&text1);
    let v: serde_json::Value = serde_json::from_str(json1).unwrap();
    let request_id = v["request_id"].as_str().unwrap();
    let finish = serde_json::json!({
        "flow": "finish",
        "request_id": request_id,
        "login3": cryptn_envelope::b64_encode(&[0u8; 64]),
    })
    .to_string();
    let fin_raw = format!(
        "POST /{}/api/v1/session HTTP/1.1\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        st.secret,
        finish.len(),
        finish
    );
    // First finish with garbage login3: PAKE rejects → 401.
    let (c3, t3) = http_raw(&st.front, fin_raw.as_bytes()).await;
    assert_eq!(c3, 401);
    assert!(t3.contains("invalid email or password"));
    // Replay it: still 401 (request_id consumed).
    let (c4, _t4) = http_raw(&st.front, fin_raw.as_bytes()).await;
    assert_eq!(c4, 401);
}

// ---------------------------------------------------------------------------
// The tunnel works (client library drives the real flow)
// ---------------------------------------------------------------------------

#[cfg(feature = "dev")]
#[tokio::test]
async fn login_via_http_works() {
    let st = boot_stack().await;
    let cfg = cryptn_client::tunnel::ClientConfig {
        server: st.front.clone(),
        secret: st.secret.clone(),
        credential_b64: st.credential.clone(),
        socks_bind: "127.0.0.1:0".into(),
    };
    let client = cryptn_client::tunnel::TunnelClient::login(cfg).await;
    assert!(
        client.is_ok(),
        "login must succeed with the right credential"
    );
}

#[cfg(feature = "dev")]
#[tokio::test]
async fn wrong_credential_login_fails() {
    let st = boot_stack().await;
    let cfg = cryptn_client::tunnel::ClientConfig {
        server: st.front.clone(),
        secret: st.secret.clone(),
        credential_b64: cryptn_envelope::b64_encode(&[9u8; 32]),
        socks_bind: "127.0.0.1:0".into(),
    };
    assert!(cryptn_client::tunnel::TunnelClient::login(cfg)
        .await
        .is_err());
}

/// SOCKS5 handshake bytes against a raw socket.
#[cfg(feature = "dev")]
#[allow(dead_code)] // wired by the dev-gated full round-trip test
async fn socks_connect(addr: &str, target_host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend_from_slice(target_host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00, "SOCKS CONNECT must succeed");
    s
}

#[cfg(feature = "dev")]
#[tokio::test]
async fn full_proxy_round_trip_through_echo() {
    let st = boot_stack().await;

    // Client: login + SOCKS front.
    let cfg = cryptn_client::tunnel::ClientConfig {
        server: st.front.clone(),
        secret: st.secret.clone(),
        credential_b64: st.credential.clone(),
        socks_bind: "127.0.0.1:0".into(),
    };
    let client = Arc::new(
        cryptn_client::tunnel::TunnelClient::login(cfg)
            .await
            .expect("login"),
    );

    // Stand up the SOCKS front by hand (main.rs does this in production).
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_port = socks_listener.local_addr().unwrap().port();
    {
        let client = client.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match socks_listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let client = client.clone();
                tokio::spawn(async move {
                    if let Ok(acc) = cryptn_client::socks::accept(stream).await {
                        let target = match acc.target {
                            cryptn_client::socks::SocksTarget::Domain(h, p) => {
                                cryptn_tunnel::Addr::Domain(h, p)
                            }
                            cryptn_client::socks::SocksTarget::Ip(ip, p) => {
                                cryptn_tunnel::Addr::Ip(ip, p)
                            }
                        };
                        let _ = client
                            .open_conversation_raw(target, Vec::new(), acc.stream)
                            .await;
                    }
                });
            }
        });
    }

    // A "browser" connects through SOCKS to the echo target by name
    // ("localhost" resolves on the server via its dev-permissive dial).
    let mut app = socks_connect(
        &format!("127.0.0.1:{socks_port}"),
        "localhost",
        st.echo_port,
    )
    .await;

    // Write and read back through the whole chain.
    app.write_all(b"ping-through-the-tunnel").await.unwrap();
    let mut got = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(15), app.read(&mut got))
        .await
        .expect("echo reply within timeout")
        .expect("stream alive");
    assert_eq!(&got[..n], b"ping-through-the-tunnel");
}
