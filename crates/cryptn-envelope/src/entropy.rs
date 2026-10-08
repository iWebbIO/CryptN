//! OS-entropy randomness for size selection (isolated module).

/// Random integer in [0, n).
pub fn random_below(n: u64) -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(0..n.max(1))
}
