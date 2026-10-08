//! HKDF key derivation helpers (isolated module).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Purpose label for the token AEAD key.
const LABEL: &[u8] = b"bearer-token-v1";

/// Derive the 32-byte token AEAD key from the 64-byte PAKE session key.
pub fn derive_aead_key(session_key: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(LABEL, &mut *okm).expect("valid OKM");
    okm
}
