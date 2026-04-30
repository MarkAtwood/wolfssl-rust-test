//! ML-KEM kem trait tests via NIST FIPS 203 ACVP deterministic vectors.
//! Requires wolfssl-wolfcrypt `kem` feature (PR #10305, mlkem_kem.rs).
//! Will not compile until PR is merged and Cargo.toml updated.
//!
//! Expected compile errors until PR #10305 lands:
//!   - `wolfssl_wolfcrypt::mlkem_kem` module not found
//!   - `kem` crate not found (must be added to Cargo.toml as dev-dependency)
//!   - `kem::Encapsulate` / `kem::Decapsulate` traits not in scope
//!
//! ## KAT design
//!
//! NIST FIPS 203 §7.2 defines a deterministic encapsulation algorithm.  The
//! ACVP test vectors supply a pre-generated encapsulation key, a decapsulation
//! key, a known ciphertext, and the expected shared secret.  To exercise the
//! kem trait with these vectors we:
//!
//!   1. Import the decapsulation key from the vector.
//!   2. Call `Decapsulate::decapsulate(ct)` on it.
//!   3. Assert the returned shared secret matches the vector.
//!
//! The round-trip test (encapsulate then decapsulate with a fresh key pair)
//! uses the trait path for both sides and only asserts that the two shared
//! secrets agree — it does not depend on knowing the ciphertext in advance.
//!
//! Upstream type referenced (current name before PR):
//!   - wolfssl_wolfcrypt::mlkem::MlKem   (wrapped MlKemKey)

mod common;

// These imports require PR #10305 (mlkem_kem.rs) and
// the `kem` dev-dependency in Cargo.toml.
use wolfssl_wolfcrypt::mlkem_kem::{MlKem512, MlKem768, MlKem1024};
use kem::{Encapsulate, Decapsulate};

// ── ACVP KAT vector path ─────────────────────────────────────────────────────

const ACVP_MLKEM_DIR: &str =
    "external/wychcheck/testvectors_acvp/ML-KEM-encapDecap-FIPS203/";

// ── Helper: load and run one ACVP ML-KEM decapsulation group ─────────────────

/// Parse a single ACVP ML-KEM encapDecap JSON file and exercise the
/// `Decapsulate` trait path for every test case.
///
/// The JSON schema follows the NIST ACVP ML-KEM server specification:
/// each `testGroup` has a `decapsulationKey` (hex) and each `test` has a
/// `cipherText` (hex) and `sharedSecret` (hex).
fn run_acvp_decapsulate<K>(path: &str)
where
    K: Decapsulate<Vec<u8>, Vec<u8>>,
    K: for<'a> TryFrom<&'a [u8]>,
    for<'a> <K as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
{
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read ACVP file {path}: {e}"));
    let root: serde_json::Value =
        serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"));

    let mut passed = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        let dk_hex = group["decapsulationKey"].as_str().expect("decapsulationKey");
        let dk_bytes = common::hex_decode(dk_hex);

        let dk = K::try_from(dk_bytes.as_slice())
            .unwrap_or_else(|e| panic!("decapsulationKey parse failed: {e:?}"));

        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let ct_hex = tc["cipherText"].as_str().expect("cipherText");
            let ss_hex = tc["sharedSecret"].as_str().expect("sharedSecret");

            let ct = common::hex_decode(ct_hex);
            let expected_ss = common::hex_decode(ss_hex);

            let computed_ss = dk
                .decapsulate(&ct)
                .unwrap_or_else(|e| panic!("tc#{tc_id}: decapsulate failed: {e:?}"));

            assert_eq!(
                computed_ss, expected_ss,
                "tc#{tc_id}: shared secret mismatch"
            );
            passed += 1;
        }
    }

    eprintln!("{path}: {passed} decapsulation KATs passed");
    assert!(passed > 0, "no KAT cases executed from {path}");
}

// ── ACVP tests: ML-KEM-512 ───────────────────────────────────────────────────

#[test]
fn mlkem512_acvp_decapsulate() {
    common::init_wolfcrypt();
    let dir = std::path::Path::new(ACVP_MLKEM_DIR);

    if !dir.exists() {
        eprintln!(
            "SKIP mlkem512_acvp_decapsulate: {} not found; run ./setup.sh",
            ACVP_MLKEM_DIR
        );
        return;
    }

    let path = dir.join("ML-KEM-512.json");
    if !path.exists() {
        eprintln!(
            "SKIP mlkem512_acvp_decapsulate: {:?} not found",
            path
        );
        return;
    }

    run_acvp_decapsulate::<MlKem512>(path.to_str().unwrap());
}

// ── ACVP tests: ML-KEM-768 ───────────────────────────────────────────────────

#[test]
fn mlkem768_acvp_decapsulate() {
    common::init_wolfcrypt();
    let dir = std::path::Path::new(ACVP_MLKEM_DIR);

    if !dir.exists() {
        eprintln!(
            "SKIP mlkem768_acvp_decapsulate: {} not found; run ./setup.sh",
            ACVP_MLKEM_DIR
        );
        return;
    }

    let path = dir.join("ML-KEM-768.json");
    if !path.exists() {
        eprintln!(
            "SKIP mlkem768_acvp_decapsulate: {:?} not found",
            path
        );
        return;
    }

    run_acvp_decapsulate::<MlKem768>(path.to_str().unwrap());
}

// ── ACVP tests: ML-KEM-1024 ──────────────────────────────────────────────────

#[test]
fn mlkem1024_acvp_decapsulate() {
    common::init_wolfcrypt();
    let dir = std::path::Path::new(ACVP_MLKEM_DIR);

    if !dir.exists() {
        eprintln!(
            "SKIP mlkem1024_acvp_decapsulate: {} not found; run ./setup.sh",
            ACVP_MLKEM_DIR
        );
        return;
    }

    let path = dir.join("ML-KEM-1024.json");
    if !path.exists() {
        eprintln!(
            "SKIP mlkem1024_acvp_decapsulate: {:?} not found",
            path
        );
        return;
    }

    run_acvp_decapsulate::<MlKem1024>(path.to_str().unwrap());
}

// ── Round-trip test: encapsulate + decapsulate agree ────────────────────────
//
// This test does not validate against an external oracle.  Its purpose is to
// verify that the kem trait implementation is self-consistent: a ciphertext
// produced by `Encapsulate::encapsulate` on the public key can be decapsulated
// by `Decapsulate::decapsulate` on the corresponding private key and yields the
// same shared secret.
//
// This is NOT used as a correctness oracle for the underlying algorithm.
// Correctness is established by the ACVP KAT tests above.

#[test]
fn mlkem768_round_trip() {
    common::init_wolfcrypt();

    // Key generation uses the wolfssl_wolfcrypt::mlkem::MlKem C API directly
    // to produce an encapsulation key (ek) and decapsulation key (dk).
    // Once PR #10305 lands, MlKem768 implements both Encapsulate (on the ek
    // half) and Decapsulate (on the dk half).

    let mut rng = wolfssl_wolfcrypt::random::RNG::new()
        .expect("RNG::new failed");

    let (ek, dk) = MlKem768::generate(&mut rng)
        .expect("MlKem768::generate failed");

    let (ct, ss_enc) = ek
        .encapsulate(&mut rng)
        .expect("encapsulate failed");

    let ss_dec = dk
        .decapsulate(&ct)
        .expect("decapsulate failed");

    assert_eq!(
        ss_enc, ss_dec,
        "encapsulated and decapsulated shared secrets must agree"
    );
}
