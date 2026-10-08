//! cryptn-server: the whole VPS side in one binary.
//!
//! Binds 0.0.0.0:80 and *is* a stock Apache2-on-Ubuntu box to everyone
//! except the operator's client, which knows the capability path and the
//! credential. No TLS anywhere, no webserver installed, one boring box.
//! All logic lives in the `cryptn_server` library; this file only wires
//! identity + bind + serve.

use cryptn_server::{build_state, serve_stack};

/// State directory (CRYPTN_STATE_DIR, default /var/lib/cryptn) and file
/// name (CRYPTN_STATE, default state.json). The name is sanitized to a
/// single path component: no separators, no `..`.
fn state_file() -> std::path::PathBuf {
    let dir = std::env::var("CRYPTN_STATE_DIR").unwrap_or_else(|_| "/var/lib/cryptn".into());
    let name = std::env::var("CRYPTN_STATE").unwrap_or_else(|_| "state.json".into());
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    if clean.is_empty() || clean.starts_with('.') || clean.contains("..") {
        std::process::exit(2);
    }
    std::path::Path::new(&dir).join(clean)
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let keyfile = state_file();
        let (setup_bytes, server_file, secret) = load_or_create_identity(&keyfile);
        let setup =
            cryptn_pake::deserialize_setup(&setup_bytes).expect("persisted setup deserializes");

        let app = build_state(
            setup,
            server_file,
            secret,
            cryptn_egress::EgressGuard::production(),
        );

        let addr = std::env::var("CRYPTN_BIND").unwrap_or_else(|_| "0.0.0.0:80".into());
        let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
        eprintln!("cryptn-server listening on {addr}");
        serve_stack(listener, app).await.expect("serve");
    });
}

/// Load persisted identity or create + persist a fresh one.
fn load_or_create_identity(keyfile: &std::path::Path) -> (Vec<u8>, Vec<u8>, String) {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Persisted {
        setup: String,
        server_file: String,
        capability_secret: String,
        credential: String,
    }

    if let Ok(text) = std::fs::read_to_string(keyfile) {
        if let Ok(p) = serde_json::from_str::<Persisted>(&text) {
            let setup = cryptn_envelope::b64_decode(&p.setup).expect("stored setup");
            let file = cryptn_envelope::b64_decode(&p.server_file).expect("stored file");
            return (setup, file, p.capability_secret);
        }
    }

    // Fresh identity: setup, credential, registration.
    let mut entropy = rand::rngs::OsRng;
    let setup = cryptn_pake::new_server_setup();
    let mut credential = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut credential);
    let export = cryptn_pake::register(&mut entropy, &setup, &credential)
        .expect("registration cannot fail with fresh inputs");

    let capability_secret = {
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        cryptn_envelope::b64url_encode(&buf)
    };

    let persisted = Persisted {
        setup: cryptn_envelope::b64_encode(&cryptn_pake::serialize_setup(&setup)),
        server_file: cryptn_envelope::b64_encode(&export.server_file),
        capability_secret: capability_secret.clone(),
        credential: cryptn_envelope::b64_encode(&export.client_material),
    };
    if let Some(parent) = keyfile.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(keyfile, serde_json::to_vec(&persisted).expect("json"))
        .expect("persist identity");

    // Print the client bundle once (operator copies it out-of-band).
    eprintln!(
        "client credential (copy to client config): {}",
        persisted.credential
    );
    eprintln!("capability path: /{capability_secret}/api/v1/…");

    (
        cryptn_pake::serialize_setup(&setup),
        export.server_file,
        capability_secret,
    )
}
