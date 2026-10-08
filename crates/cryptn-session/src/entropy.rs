//! Fresh random bytes from the OS entropy source.

/// Fill `buf` with cryptographically random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    use rand::rngs::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(buf);
}
