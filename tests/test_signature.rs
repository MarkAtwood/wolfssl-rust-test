//! Signature trait tests (ECDSA, Ed25519, Ed448, RSA via signature::{Signer,Verifier}).
//! Requires wolfssl-wolfcrypt `signature` feature (PR #10248, ecdsa.rs + rsa_pkcs1v15.rs).
//! Will not compile until PR is merged and Cargo.toml updated.
//!
//! Expected compile errors until PR #10248 lands:
//!   - `wolfssl_wolfcrypt::ecdsa` module not found
//!   - `wolfssl_wolfcrypt::rsa_pkcs1v15` module not found
//!   - `signature` crate not found (must be added to Cargo.toml as dev-dependency)
//!   - `signature::Signer` / `signature::Verifier` traits not in scope
//!
//! Upstream types referenced (current names before PR):
//!   - wolfssl_wolfcrypt::ecc::ECC   (ECDSA key)
//!   - wolfssl_wolfcrypt::ed25519::Ed25519  (Ed25519 key)

mod common;

// These imports require PR #10248 (ecdsa.rs + rsa_pkcs1v15.rs) and
// the `signature` dev-dependency in Cargo.toml.
use wolfssl_wolfcrypt::ecdsa::{EcdsaSigningKey, EcdsaVerifyingKey};
use wolfssl_wolfcrypt::ed25519_sig::Ed25519SigningKey;
use wolfssl_wolfcrypt::rsa_pkcs1v15::{RsaPkcs1v15SigningKey, RsaPkcs1v15VerifyingKey};
use signature::{Signer, Verifier};

// ── Wycheproof file paths ────────────────────────────────────────────────────

const WYCHEPROOF_ECDSA_P256_SHA256: &str =
    "external/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json";

const WYCHEPROOF_ED25519: &str =
    "external/wychcheck/testvectors_rfc/rfc8032_eddsa_test.json";

const WYCHEPROOF_RSA_2048_SHA256: &str =
    "external/wycheproof/testvectors_v1/rsa_signature_2048_sha256_test.json";

// ── ECDSA secp256r1 / SHA-256 ────────────────────────────────────────────────

/// Run Wycheproof ECDSA secp256r1-SHA-256 vectors (verify path only).
///
/// The verify path does not require a signing key or RNG — it reads the DER
/// public key from the test group and calls `Verifier::verify`.
#[test]
fn ecdsa_secp256r1_sha256_wycheproof() {
    common::init_wolfcrypt();

    if !std::path::Path::new(WYCHEPROOF_ECDSA_P256_SHA256).exists() {
        eprintln!(
            "SKIP ecdsa_secp256r1_sha256_wycheproof: {} not found; run ./setup.sh",
            WYCHEPROOF_ECDSA_P256_SHA256
        );
        return;
    }

    let content = std::fs::read_to_string(WYCHEPROOF_ECDSA_P256_SHA256)
        .expect("failed to read Wycheproof ECDSA file");
    let root: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON in Wycheproof ECDSA file");

    let mut passed = 0usize;
    let mut skipped = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        // Public key is DER-encoded SubjectPublicKeyInfo.
        let der_hex = group["publicKeyDer"].as_str().expect("publicKeyDer");
        let pub_key_der = common::hex_decode(der_hex);

        let vk = match EcdsaVerifyingKey::from_sec1_der(&pub_key_der) {
            Ok(k) => k,
            Err(_) => {
                skipped += group["tests"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0);
                continue;
            }
        };

        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let result = tc["result"].as_str().unwrap_or("invalid");
            let msg_hex = tc["msg"].as_str().expect("msg");
            let sig_hex = tc["sig"].as_str().expect("sig");

            let msg = common::hex_decode(msg_hex);
            let sig_bytes = common::hex_decode(sig_hex);

            // The signature::Verifier impl is expected to hash internally (SHA-256).
            let sig = match signature::Signature::from_bytes(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    // Malformed DER — only valid vectors should be well-formed.
                    if result == "valid" {
                        panic!("tc#{tc_id}: valid vector has unparseable signature");
                    }
                    passed += 1;
                    continue;
                }
            };

            let verify_result = vk.verify(&msg, &sig);
            match result {
                "valid" => {
                    verify_result.unwrap_or_else(|e| {
                        panic!("tc#{tc_id}: valid ECDSA signature rejected: {e}")
                    });
                }
                "invalid" => {
                    assert!(
                        verify_result.is_err(),
                        "tc#{tc_id}: invalid ECDSA signature was accepted"
                    );
                }
                _ => {
                    // "acceptable" — we don't assert either way; count as skipped.
                    skipped += 1;
                    continue;
                }
            }
            passed += 1;
        }
    }

    eprintln!(
        "ecdsa_secp256r1_sha256_wycheproof: {passed} cases checked, {skipped} skipped"
    );
    assert!(passed > 0, "no test cases were executed");
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────

/// Run Wycheproof / RFC 8032 Ed25519 test vectors (verify path only).
#[test]
fn ed25519_wycheproof() {
    common::init_wolfcrypt();

    if !std::path::Path::new(WYCHEPROOF_ED25519).exists() {
        eprintln!(
            "SKIP ed25519_wycheproof: {} not found; run ./setup.sh",
            WYCHEPROOF_ED25519
        );
        return;
    }

    let content = std::fs::read_to_string(WYCHEPROOF_ED25519)
        .expect("failed to read Ed25519 test vector file");
    let root: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON in Ed25519 file");

    let mut passed = 0usize;
    let mut skipped = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        let schema = group["type"].as_str().unwrap_or("");
        if schema != "EddsaVerify" {
            skipped += group["tests"]
                .as_array()
                .map(|v| v.len())
                .unwrap_or(0);
            continue;
        }

        let pub_key_hex = group["publicKey"]["pk"].as_str().expect("pk");
        let pub_key_bytes = common::hex_decode(pub_key_hex);

        // Ed25519 public key is 32 raw bytes.
        let vk = match Ed25519SigningKey::from_public_key_bytes(&pub_key_bytes) {
            Ok(k) => k,
            Err(_) => {
                skipped += group["tests"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0);
                continue;
            }
        };

        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let result = tc["result"].as_str().unwrap_or("invalid");
            let msg_hex = tc["msg"].as_str().expect("msg");
            let sig_hex = tc["sig"].as_str().expect("sig");

            let msg = common::hex_decode(msg_hex);
            let sig_bytes = common::hex_decode(sig_hex);

            // Ed25519 signatures are 64 bytes.
            let sig = match signature::Signature::from_bytes(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    if result == "valid" {
                        panic!("tc#{tc_id}: valid Ed25519 vector has unparseable signature");
                    }
                    passed += 1;
                    continue;
                }
            };

            let verify_result = vk.verify(&msg, &sig);
            match result {
                "valid" => {
                    verify_result.unwrap_or_else(|e| {
                        panic!("tc#{tc_id}: valid Ed25519 signature rejected: {e}")
                    });
                }
                "invalid" => {
                    assert!(
                        verify_result.is_err(),
                        "tc#{tc_id}: invalid Ed25519 signature was accepted"
                    );
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            }
            passed += 1;
        }
    }

    eprintln!(
        "ed25519_wycheproof: {passed} cases checked, {skipped} skipped"
    );
    assert!(passed > 0, "no test cases were executed");
}

// ── RSA PKCS#1 v1.5 / SHA-256 ────────────────────────────────────────────────

/// Run Wycheproof RSA-2048-SHA256 PKCS#1 v1.5 verify vectors.
#[test]
fn rsa_pkcs1v15_2048_sha256_wycheproof() {
    common::init_wolfcrypt();

    if !std::path::Path::new(WYCHEPROOF_RSA_2048_SHA256).exists() {
        eprintln!(
            "SKIP rsa_pkcs1v15_2048_sha256_wycheproof: {} not found; run ./setup.sh",
            WYCHEPROOF_RSA_2048_SHA256
        );
        return;
    }

    let content = std::fs::read_to_string(WYCHEPROOF_RSA_2048_SHA256)
        .expect("failed to read Wycheproof RSA file");
    let root: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON in Wycheproof RSA file");

    let mut passed = 0usize;
    let mut skipped = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        let key_der_hex = group["publicKeyDer"].as_str().expect("publicKeyDer");
        let key_der = common::hex_decode(key_der_hex);

        let vk = match RsaPkcs1v15VerifyingKey::from_der(&key_der) {
            Ok(k) => k,
            Err(_) => {
                skipped += group["tests"]
                    .as_array()
                    .map(|v| v.len())
                    .unwrap_or(0);
                continue;
            }
        };

        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let result = tc["result"].as_str().unwrap_or("invalid");
            let msg_hex = tc["msg"].as_str().expect("msg");
            let sig_hex = tc["sig"].as_str().expect("sig");

            let msg = common::hex_decode(msg_hex);
            let sig_bytes = common::hex_decode(sig_hex);

            let sig = match signature::Signature::from_bytes(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    if result == "valid" {
                        panic!("tc#{tc_id}: valid RSA vector has unparseable signature");
                    }
                    passed += 1;
                    continue;
                }
            };

            let verify_result = vk.verify(&msg, &sig);
            match result {
                "valid" => {
                    verify_result.unwrap_or_else(|e| {
                        panic!("tc#{tc_id}: valid RSA signature rejected: {e}")
                    });
                }
                "invalid" => {
                    assert!(
                        verify_result.is_err(),
                        "tc#{tc_id}: invalid RSA signature was accepted"
                    );
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            }
            passed += 1;
        }
    }

    eprintln!(
        "rsa_pkcs1v15_2048_sha256_wycheproof: {passed} cases checked, {skipped} skipped"
    );
    assert!(passed > 0, "no test cases were executed");
}
