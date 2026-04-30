//! digest::Digest trait tests for SHA/SHA3 algorithms.
//!
//! Oracle: NIST FIPS 180-4 Appendix B (SHA-256/384/512) and FIPS 202 (SHA3).
//! Inline KAT vectors from testvectors/nist/sha_inline.rs (SHA-256, SHA-512,
//! SHA3-256) and embedded directly here (SHA-384, SHA3-512).
//!
//! NOTE: This file requires wolfssl-wolfcrypt with the `digest` feature
//! (added by upstream PR #10248, sha_digest.rs). It will NOT compile until
//! that PR is present in the local wolfssl checkout. The compile errors are
//! intentional — they document the gap between this test harness and the
//! current local wolfssl-wolfcrypt crate.

mod common;

#[path = "../testvectors/nist/sha_inline.rs"]
mod sha_inline;

use sha_inline::TestVector;

// Import the wolfssl-wolfcrypt SHA types that implement digest::Digest.
// These types exist today; the digest::Digest impl is added by sha_digest.rs
// (PR #10248). Until that PR lands, the `use digest::Digest` line below and
// any `.digest()` / `.update()` / `.finalize()` calls will fail to compile.
use wolfssl_wolfcrypt::sha::{SHA256, SHA384, SHA3_256, SHA3_512, SHA512};

use digest::Digest;

// ---------------------------------------------------------------------------
// Compile-time trait checks — zero-cost, verify the trait bound is satisfied.
// These will be the first lines to fail when PR #10248 is missing.
// ---------------------------------------------------------------------------

fn _check_sha256_is_digest()  { let _: fn() -> SHA256  = || SHA256::new();  }
fn _check_sha384_is_digest()  { let _: fn() -> SHA384  = || SHA384::new();  }
fn _check_sha512_is_digest()  { let _: fn() -> SHA512  = || SHA512::new();  }
fn _check_sha3_256_is_digest(){ let _: fn() -> SHA3_256 = || SHA3_256::new(); }
fn _check_sha3_512_is_digest(){ let _: fn() -> SHA3_512 = || SHA3_512::new(); }

// ---------------------------------------------------------------------------
// Generic runner: one-shot and incremental update paths.
// ---------------------------------------------------------------------------

fn run_digest_vectors<D: Digest>(vectors: &[TestVector]) {
    for (i, vec) in vectors.iter().enumerate() {
        let input = vec.input.as_bytes();
        let expected = common::hex_decode(vec.output);

        // One-shot path
        let result = D::digest(input);
        assert_eq!(
            result.as_slice(),
            expected.as_slice(),
            "one-shot failed for vector {i}: input={:?}",
            vec.input
        );

        // Incremental update path
        let mut hasher = D::new();
        hasher.update(input);
        let result2 = hasher.finalize();
        assert_eq!(
            result2.as_slice(),
            expected.as_slice(),
            "incremental update failed for vector {i}: input={:?}",
            vec.input
        );
    }
}

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4 Appendix B vectors from sha_inline.rs
// ---------------------------------------------------------------------------

#[test]
fn sha256_nist_fips180_4() {
    common::init_wolfcrypt();
    run_digest_vectors::<SHA256>(sha_inline::SHA256);
}

// ---------------------------------------------------------------------------
// SHA-384 — FIPS 180-4 Appendix C vectors (embedded directly)
//
// Source: NIST FIPS 180-4, Appendix C.2 (SHA-384 example)
//   SHA-384("abc") =
//     cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163
//     1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
// ---------------------------------------------------------------------------

const SHA384_VECTORS: &[TestVector] = &[
    // Empty string — NIST FIPS 180-4 / RFC 6234 §8.1
    TestVector {
        input: "",
        output: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    // "abc" — NIST FIPS 180-4 Appendix C.2
    TestVector {
        input: "abc",
        output: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    },
];

#[test]
fn sha384_nist_fips180_4() {
    common::init_wolfcrypt();
    run_digest_vectors::<SHA384>(&SHA384_VECTORS);
}

// ---------------------------------------------------------------------------
// SHA-512 — FIPS 180-4 Appendix C vectors from sha_inline.rs
// ---------------------------------------------------------------------------

#[test]
fn sha512_nist_fips180_4() {
    common::init_wolfcrypt();
    run_digest_vectors::<SHA512>(sha_inline::SHA512);
}

// ---------------------------------------------------------------------------
// SHA3-256 — FIPS 202 vectors from sha_inline.rs
// ---------------------------------------------------------------------------

#[test]
fn sha3_256_nist_fips202() {
    common::init_wolfcrypt();
    run_digest_vectors::<SHA3_256>(sha_inline::SHA3_256);
}

// ---------------------------------------------------------------------------
// SHA3-512 — FIPS 202 vectors (embedded directly)
//
// Source: NIST FIPS 202, Appendix A / NIST CAVS SHA3 byte-oriented sample
//   SHA3-512("") =
//     a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6
//     15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
// ---------------------------------------------------------------------------

const SHA3_512_VECTORS: &[TestVector] = &[
    // Empty string — NIST FIPS 202 Appendix A / NIST CAVS
    TestVector {
        input: "",
        output: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    },
    // "abc" — NIST FIPS 202 / pyca/cryptography cross-check
    TestVector {
        input: "abc",
        output: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    },
];

#[test]
fn sha3_512_nist_fips202() {
    common::init_wolfcrypt();
    run_digest_vectors::<SHA3_512>(&SHA3_512_VECTORS);
}
