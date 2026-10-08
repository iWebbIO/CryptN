//! Size shaping: pad sealed records so JSON bodies land in a realistic
//! chat-message length distribution (restls-style record-size shaping).
//!
//! Buckets approximate real chat traffic: tiny acks, short messages, medium
//! notes, occasional long ones — plus extra padding on a conversation's
//! first records (NaiveProxy first-reads shaping). All randomness here is
//! size-bucket selection, not cryptography: OS-entropic thread_rng exceeds
//! the need, and no secret depends on it.

use crate::entropy::random_below;

/// Target length buckets (bytes of padded plaintext), with weights a chat
/// app plausibly produces. Padding is applied *before* AEAD sealing by the
/// caller, so it is integrity-protected like everything else.
const BUCKETS: [(usize, u32); 6] = [
    (64, 10),   // short ack/typing events
    (128, 25),  // brief messages
    (256, 30),  // typical message
    (512, 20),  // longer message
    (1024, 10), // paragraph
    (2048, 5),  // rare long paste
];

/// First records of a conversation get extra headroom (first-reads shape).
const FIRST_RECORD_EXTRA: usize = 384;

fn total_weight() -> u32 {
    BUCKETS.iter().map(|(_, w)| w).sum()
}

/// Pick a bucket target for a record; `is_first` adds first-record padding.
fn pick_target(is_first: bool) -> usize {
    let mut roll = random_below(total_weight() as u64) as u32;
    let mut target = BUCKETS[0].0;
    for (size, weight) in BUCKETS {
        if roll < weight {
            target = size;
            break;
        }
        roll -= weight;
    }
    if is_first {
        target += FIRST_RECORD_EXTRA;
    }
    target
}

/// Pad `plaintext` (the caller seals AFTER this) up to a bucket size so the
/// eventual ciphertext+JSON length draws from the distribution. Layout:
/// `plaintext || zeros || pad_len(2, big-endian)` — the marker rides at the
/// very end, covered by the AEAD tag like everything else.
/// An already-oversized plaintext rides as-is (a real app has long messages
/// too; bulk data uses the attachments lane).
pub fn pad_plaintext(plaintext: &[u8], is_first: bool) -> Vec<u8> {
    let target = pick_target(is_first);
    if plaintext.len() + 2 >= target {
        return plaintext.to_vec();
    }
    let pad_len = target - plaintext.len() - 2;
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(plaintext);
    out.resize(target - 2, 0);
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out
}

/// Strip the padding added by `pad_plaintext` (after AEAD open). Validates
/// that the claimed pad region is all zeros; a record whose tail does not
/// match the layout passes through unchanged (oversized, unpadded records).
pub fn strip_plaintext(padded: &[u8]) -> Vec<u8> {
    if padded.len() < 2 {
        return padded.to_vec();
    }
    let n = padded.len();
    let pad_len = u16::from_be_bytes([padded[n - 2], padded[n - 1]]) as usize;
    if 2 + pad_len > n || pad_len == 0 {
        return padded.to_vec();
    }
    let end = n - 2 - pad_len;
    if padded[end..n - 2].iter().any(|&b| b != 0) {
        return padded.to_vec(); // not our padding
    }
    padded[..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_strip_round_trip() {
        for size in [0usize, 10, 60, 100, 300, 900] {
            let pt = vec![0xA5u8; size];
            let padded = pad_plaintext(&pt, false);
            assert_eq!(strip_plaintext(&padded), pt, "size {size}");
        }
    }

    #[test]
    fn oversized_passes_through() {
        let pt = vec![1u8; 5000];
        assert_eq!(pad_plaintext(&pt, false), pt);
        assert_eq!(strip_plaintext(&pt), pt);
    }

    #[test]
    fn buckets_are_realistic() {
        let pt = b"hi";
        for _ in 0..20 {
            let padded = pad_plaintext(pt, false);
            let len = padded.len();
            assert!(
                BUCKETS.iter().any(|(s, _)| len == *s),
                "padded len {len} not a bucket"
            );
        }
    }

    #[test]
    fn first_records_get_extra() {
        let pt = b"x";
        for _ in 0..20 {
            let padded = pad_plaintext(pt, true);
            let len = padded.len();
            assert!(len >= 448, "first record should be >= 64+384, got {len}");
        }
    }
}
