//! cryptn-client: local SOCKS5 proxy fronting the persona-tunnel client.

use std::sync::Arc;

use cryptn_client::tunnel::{ClientConfig, TunnelClient};

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let cfg = ClientConfig {
            server: std::env::var("CRYPTN_SERVER").unwrap_or_else(|_| "127.0.0.1:80".into()),
            secret: std::env::var("CRYPTN_SECRET").expect("CRYPTN_SECRET"),
            credential_b64: std::env::var("CRYPTN_CREDENTIAL").expect("CRYPTN_CREDENTIAL"),
            socks_bind: std::env::var("CRYPTN_SOCKS").unwrap_or_else(|_| "127.0.0.1:1080".into()),
        };

        let client = match TunnelClient::login(cfg.clone()).await {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("login failed: {e}");
                std::process::exit(1);
            }
        };

        let listener = tokio::net::TcpListener::bind(&cfg.socks_bind)
            .await
            .expect("bind socks");
        eprintln!("cryptn-client SOCKS5 on {}", cfg.socks_bind);

        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let client = client.clone();
            tokio::spawn(async move {
                match cryptn_client::socks::accept(stream).await {
                    Ok(acc) => {
                        let target = match acc.target {
                            cryptn_client::socks::SocksTarget::Domain(h, p) => {
                                cryptn_tunnel::Addr::Domain(h, p)
                            }
                            cryptn_client::socks::SocksTarget::Ip(ip, p) => {
                                cryptn_tunnel::Addr::Ip(ip, p)
                            }
                        };
                        if let Err(e) = client
                            .open_conversation_raw(target, Vec::new(), acc.stream)
                            .await
                        {
                            eprintln!("conversation open failed: {e}");
                        }
                    }
                    Err(_e) => {
                        // Handshake failed; the acceptor already replied or
                        // the connection is dead.
                    }
                }
            });
        }
    });
}
