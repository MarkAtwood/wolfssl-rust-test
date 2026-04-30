//! RNG trait tests for rand_core::TryCryptoRng impl.
//!
//! No external oracle is appropriate for DRBG output (wolfCrypt runs
//! self-tests internally). Tests verify: trait bound, non-zero output,
//! successive-call divergence, and edge cases.

mod common;

use rand_core::TryRng;
use wolfssl_wolfcrypt::random::RNG;

// Compile-time trait bound proof — if this function compiles, the impl exists.
fn _assert_try_crypto_rng<R: rand_core::TryCryptoRng>(_: &R) {}

/// Verify the TryCryptoRng marker trait bound holds at compile time.
#[test]
fn rng_implements_try_crypto_rng() {
    common::init_wolfcrypt();
    let rng = RNG::new().expect("RNG init failed");
    _assert_try_crypto_rng(&rng);
}

/// try_fill_bytes must succeed and produce non-zero output.
///
/// The all-zeros check is probabilistic: P(false failure) = 2^-256 at 32 bytes.
#[test]
fn rng_try_fill_bytes_nonzero() {
    common::init_wolfcrypt();
    let mut rng = RNG::new().expect("RNG init failed");
    let mut buf = [0u8; 32];
    rng.try_fill_bytes(&mut buf).expect("try_fill_bytes failed");
    assert_ne!(buf, [0u8; 32], "RNG returned all zeros");
}

/// Successive calls must produce different output.
///
/// P(false failure) = 2^-256 at 32 bytes.
#[test]
fn rng_successive_calls_differ() {
    common::init_wolfcrypt();
    let mut rng = RNG::new().expect("RNG init failed");
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    rng.try_fill_bytes(&mut buf1).expect("first fill failed");
    rng.try_fill_bytes(&mut buf2).expect("second fill failed");
    assert_ne!(buf1, buf2, "RNG produced identical successive 32-byte outputs");
}

/// Zero-length fill must succeed without error or panic.
#[test]
fn rng_zero_length_fill_ok() {
    common::init_wolfcrypt();
    let mut rng = RNG::new().expect("RNG init failed");
    rng.try_fill_bytes(&mut []).expect("zero-length fill should succeed");
}

/// Two independent RNG instances must not produce the same 32-byte block.
///
/// P(false failure) = 2^-256.
#[test]
fn rng_independent_instances_differ() {
    common::init_wolfcrypt();
    let mut rng1 = RNG::new().expect("RNG1 init failed");
    let mut rng2 = RNG::new().expect("RNG2 init failed");
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];
    rng1.try_fill_bytes(&mut buf1).expect("rng1 fill failed");
    rng2.try_fill_bytes(&mut buf2).expect("rng2 fill failed");
    assert_ne!(buf1, buf2, "independent RNG instances produced identical output");
}
