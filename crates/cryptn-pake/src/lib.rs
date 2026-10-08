//! OPAQUE (RFC 9380) login flow over Ristretto255.
//!
//! Nothing password-derived ever crosses the wire; the derived session key
//! feeds the record layer's HKDF. Wire messages are base64 blobs inside the
//! persona's JSON (`login1`/`login2`/`login3` fields of `POST /session`).
//!
//! The credential identifier is a fixed deployment constant decoupled from
//! any visible username.

mod ids;

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

/// The deployment ciphersuite: Ristretto255 OPRF + TripleDH over
/// Curve25519 with SHA-512, identity KSF (the operator credential is a
/// generated high-entropy secret, not a human password — no stretching
/// needed, and login stays fast).
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = voprf::Ristretto255;
    type KeyExchange = TripleDh<opaque_ke::Curve25519, Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// Bytes of a protocol message on the wire.
pub type Wire = Vec<u8>;

/// Errors from the PAKE flow. Deliberately uninformative on the wire: the
/// API layer maps every failure to the persona's generic error JSON.
#[derive(Debug, thiserror::Error)]
pub enum PakeError {
    /// Internal protocol failure (bad message, bad state, deserialization).
    #[error("pake protocol error")]
    Protocol(#[from] opaque_ke::errors::ProtocolError),
    /// Input did not decode into a protocol message.
    #[error("invalid message")]
    Invalid,
}

/// The long-term server setup (serialized at deploy, deserialized at boot).
pub type Setup = ServerSetup<Suite>;

/// Generate a fresh server setup (deploy-time only): a fresh keypair plus
/// OPRF seed, drawn from the OS entropy source.
pub fn new_server_setup() -> Setup {
    let mut entropy = rand::rngs::OsRng;
    ServerSetup::<Suite>::new(&mut entropy)
}

/// Serialize the server setup for persistence.
pub fn serialize_setup(setup: &Setup) -> Vec<u8> {
    setup.serialize().to_vec()
}

/// Restore a server setup from persisted bytes.
pub fn deserialize_setup(bytes: &[u8]) -> Result<Setup, PakeError> {
    ServerSetup::deserialize(bytes).map_err(|_| PakeError::Invalid)
}

/// Envelope for the out-of-band credential export given to the operator.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CredentialExport {
    /// Password-file bytes for the server (store server-side).
    pub server_file: Vec<u8>,
    /// The secret credential material the client needs (client-side, secret).
    pub client_material: Vec<u8>,
}

/// Run the full registration flow locally (both sides) and produce the
/// export pair. `credential` must be a generated 256-bit secret.
pub fn register(
    rng: &mut (impl CryptoRng + RngCore),
    setup: &Setup,
    credential: &[u8],
) -> Result<CredentialExport, PakeError> {
    let start = ClientRegistration::<Suite>::start(rng, credential)?;
    let server_start =
        ServerRegistration::<Suite>::start(setup, start.message, ids::CREDENTIAL_ID)?;
    let finish = start.state.finish(
        rng,
        credential,
        server_start.message,
        ClientRegistrationFinishParameters::default(),
    )?;
    let file = ServerRegistration::finish(finish.message);
    Ok(CredentialExport {
        server_file: file.serialize().to_vec(),
        client_material: credential.to_vec(),
    })
}

/// Client-side login state between steps.
pub struct ClientLoginState {
    state: ClientLogin<Suite>,
}

/// Client step 1: produce login1 bytes; keep the state for step 2.
pub fn client_login_start(
    rng: &mut (impl CryptoRng + RngCore),
    credential: &[u8],
) -> Result<(Wire, ClientLoginState), PakeError> {
    let res = ClientLogin::<Suite>::start(rng, credential)?;
    Ok((
        res.message.serialize().to_vec(),
        ClientLoginState { state: res.state },
    ))
}

/// Client step 2: consume login2 bytes, produce login3 + session + export keys.
pub fn client_login_finish(
    state: ClientLoginState,
    credential: &[u8],
    login2: &[u8],
) -> Result<(Wire, [u8; 64], [u8; 64]), PakeError> {
    let msg = opaque_ke::CredentialResponse::<Suite>::deserialize(login2)
        .map_err(|_| PakeError::Invalid)?;
    let res = state
        .state
        .finish(
            &mut OsRng,
            credential,
            msg,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| PakeError::Invalid)?;
    let session_key: [u8; 64] = res
        .session_key
        .as_slice()
        .try_into()
        .map_err(|_| PakeError::Invalid)?;
    let export_key: [u8; 64] = res
        .export_key
        .as_slice()
        .try_into()
        .map_err(|_| PakeError::Invalid)?;
    Ok((res.message.serialize().to_vec(), session_key, export_key))
}

/// Server-side login state between steps.
pub struct ServerLoginState {
    state: ServerLogin<Suite>,
}

/// Server step 1: consume login1, produce login2; keep the state.
pub fn server_login_start(
    rng: &mut (impl CryptoRng + RngCore),
    setup: &Setup,
    server_file: &[u8],
    login1: &[u8],
) -> Result<(Wire, ServerLoginState), PakeError> {
    let file =
        ServerRegistration::<Suite>::deserialize(server_file).map_err(|_| PakeError::Invalid)?;
    let msg = opaque_ke::CredentialRequest::<Suite>::deserialize(login1)
        .map_err(|_| PakeError::Invalid)?;
    let res = ServerLogin::start(
        rng,
        setup,
        Some(file),
        msg,
        ids::CREDENTIAL_ID,
        ServerLoginParameters::default(),
    )?;
    Ok((
        res.message.serialize().to_vec(),
        ServerLoginState { state: res.state },
    ))
}

/// Server step 2: consume login3, obtain the session key.
pub fn server_login_finish(state: ServerLoginState, login3: &[u8]) -> Result<[u8; 64], PakeError> {
    let msg = opaque_ke::CredentialFinalization::<Suite>::deserialize(login3)
        .map_err(|_| PakeError::Invalid)?;
    let res = state
        .state
        .finish(msg, ServerLoginParameters::default())
        .map_err(|_| PakeError::Invalid)?;
    let session_key: [u8; 64] = res
        .session_key
        .as_slice()
        .try_into()
        .map_err(|_| PakeError::Invalid)?;
    Ok(session_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Vec<u8> {
        let mut c = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut c);
        c.to_vec()
    }

    #[test]
    fn full_registration_and_login_round_trip() {
        let mut entropy = rand::rngs::OsRng;
        let setup = new_server_setup();
        let cred = credential();

        let export = register(&mut entropy, &setup, &cred).unwrap();

        let (login1, cstate) = client_login_start(&mut entropy, &cred).unwrap();
        let (login2, sstate) =
            server_login_start(&mut entropy, &setup, &export.server_file, &login1).unwrap();
        let (login3, ckey, _ekey) = client_login_finish(cstate, &cred, &login2).unwrap();
        let skey = server_login_finish(sstate, &login3).unwrap();

        assert_eq!(ckey, skey, "both sides must derive the same session key");
    }

    #[test]
    fn wrong_credential_fails() {
        let mut entropy = rand::rngs::OsRng;
        let setup = new_server_setup();
        let wrong = credential();
        let export = register(&mut entropy, &setup, &wrong).unwrap();

        // Registered credential is `wrong`; the client tries a different one.
        let (login1, cstate) = client_login_start(&mut entropy, &credential()).unwrap();
        let (login2, _sstate) =
            server_login_start(&mut entropy, &setup, &export.server_file, &login1).unwrap();
        assert!(client_login_finish(cstate, &credential(), &login2).is_err());
    }

    #[test]
    fn login1_is_unique_per_attempt() {
        let mut entropy = rand::rngs::OsRng;
        let cred = credential();
        let (login1a, _) = client_login_start(&mut entropy, &cred).unwrap();
        let (login1b, _) = client_login_start(&mut entropy, &cred).unwrap();
        assert_ne!(login1a, login1b);
    }
}
