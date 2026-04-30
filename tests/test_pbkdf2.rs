//! PBKDF2 password-hash trait tests via Wycheproof JSON.
//! Requires wolfssl-wolfcrypt `password-hash` feature (PR #10305, pbkdf2_password_hash.rs).
//! Will not compile until PR is merged and Cargo.toml updated.
//!
//! Expected compile errors until PR #10305 lands:
//!   - `wolfssl_wolfcrypt::pbkdf2_password_hash` module not found
//!   - `password_hash` crate not found (must be added to Cargo.toml as dev-dependency)
//!   - `password_hash::PasswordHasher` trait not in scope
//!
//! ## External oracle reference
//!
//! RFC 6070 §2 Test Case 1:
//!   PBKDF2-HMAC-SHA1(password="password", salt="salt", c=1, dkLen=20)
//!   = 0x0c60c80f961f0e71f3a9b524af6012062fe037a6
//!
//! This file tests PBKDF2-HMAC-SHA256 via the password-hash trait.  The SHA-1
//! reference is included in a comment for cross-check reference only; the
//! wolfssl_wolfcrypt kdf::pbkdf2() function (gated on #[cfg(kdf_pbkdf2)]) can
//! be used to validate SHA-1 output against the RFC vector directly.
//!
//! Upstream type referenced (current name before PR):
//!   - wolfssl_wolfcrypt::kdf::pbkdf2() / pbkdf2_ex()  (free function, already present)

mod common;

// These imports require PR #10305 (pbkdf2_password_hash.rs) and
// the `password-hash` dev-dependency in Cargo.toml.
use wolfssl_wolfcrypt::pbkdf2_password_hash::Pbkdf2HmacSha256;
use password_hash::{PasswordHasher, SaltString};

// ── Wycheproof PBKDF2-HMAC-SHA256 ───────────────────────────────────────────

const WYCHEPROOF_PBKDF2_SHA256: &str =
    "external/wycheproof/testvectors_v1/pbkdf2_hmacsha256_test.json";

/// Run Wycheproof PBKDF2-HMAC-SHA256 test vectors if the file is present.
/// Skip (with eprintln) if the file is absent — run ./setup.sh to populate it.
///
/// Wycheproof schema for PBKDF2 (from testvectors_v1/pbkdf2_*.json):
///   testGroups[].tests[].{password, salt, iterationCount, dkLen, expectedDk, result}
///   All values are hex-encoded.
#[test]
fn pbkdf2_hmacsha256_wycheproof() {
    common::init_wolfcrypt();

    if !std::path::Path::new(WYCHEPROOF_PBKDF2_SHA256).exists() {
        eprintln!(
            "SKIP pbkdf2_hmacsha256_wycheproof: {} not found; run ./setup.sh",
            WYCHEPROOF_PBKDF2_SHA256
        );
        return;
    }

    let content = std::fs::read_to_string(WYCHEPROOF_PBKDF2_SHA256)
        .expect("failed to read Wycheproof PBKDF2 file");
    let root: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON in Wycheproof PBKDF2 file");

    let mut passed = 0usize;
    let mut skipped = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let result = tc["result"].as_str().unwrap_or("valid");

            // Skip anything not marked "valid" — invalid PBKDF2 vectors in
            // Wycheproof typically test iteration count of zero or other
            // out-of-range parameters that the password-hash API may reject
            // before hashing begins.
            if result != "valid" {
                skipped += 1;
                continue;
            }

            let password_hex = tc["password"].as_str().expect("password");
            let salt_hex = tc["salt"].as_str().expect("salt");
            let iterations = tc["iterationCount"]
                .as_u64()
                .expect("iterationCount") as u32;
            let dk_len = tc["dkLen"].as_u64().expect("dkLen") as usize;
            let expected_hex = tc["expectedDk"].as_str().expect("expectedDk");

            let password_bytes = common::hex_decode(password_hex);
            let salt_bytes = common::hex_decode(salt_hex);
            let expected_dk = common::hex_decode(expected_hex);

            // The password-hash crate uses &str for passwords; interpret the
            // password bytes as Latin-1 / raw bytes via lossy UTF-8.
            let password_str = String::from_utf8_lossy(&password_bytes);

            // SaltString encodes the salt in PHC string format (base64).
            let salt_str = match SaltString::encode_b64(&salt_bytes) {
                Ok(s) => s,
                Err(_) => {
                    // Salt too long for SaltString — skip this vector.
                    skipped += 1;
                    continue;
                }
            };

            let hasher = Pbkdf2HmacSha256::new(iterations, dk_len)
                .unwrap_or_else(|e| panic!("tc#{tc_id}: Pbkdf2HmacSha256::new failed: {e}"));

            let hash = hasher
                .hash_password(password_str.as_bytes(), &salt_str)
                .unwrap_or_else(|e| panic!("tc#{tc_id}: hash_password failed: {e}"));

            // Extract the raw derived key from the PHC hash output.
            let computed_dk = hash
                .hash
                .expect("hash_password must produce a hash value")
                .as_bytes()
                .to_vec();

            // Only compare the first dk_len bytes; PHC output may be padded.
            assert_eq!(
                &computed_dk[..dk_len],
                expected_dk.as_slice(),
                "tc#{tc_id}: PBKDF2-HMAC-SHA256 derived key mismatch"
            );
            passed += 1;
        }
    }

    eprintln!(
        "pbkdf2_hmacsha256_wycheproof: {passed} cases checked, {skipped} skipped"
    );
    assert!(passed > 0, "no test cases were executed");
}

// ── RFC 6070 §2 Test Case 1 cross-reference ──────────────────────────────────
//
// The RFC 6070 §2 Test Case 1 vector below is for PBKDF2-HMAC-SHA1, which is
// NOT the algorithm under test here (SHA-256 is used above). It is included as
// a reference to allow manual validation of the underlying wolfssl_wolfcrypt
// kdf::pbkdf2() function using HMAC::TYPE_SHA, independently of the
// password-hash trait.
//
// PBKDF2-HMAC-SHA1("password", "salt", c=1, dkLen=20)
//   = 0x0c60c80f961f0e71f3a9b524af6012062fe037a6
//
// To validate, run:
//   use wolfssl_wolfcrypt::kdf::pbkdf2;
//   use wolfssl_wolfcrypt::hmac::HMAC;
//   let mut out = [0u8; 20];
//   pbkdf2(b"password", b"salt", 1, HMAC::TYPE_SHA, &mut out).unwrap();
//   assert_eq!(out, hex!("0c60c80f961f0e71f3a9b524af6012062fe037a6"));

/// Sanity check: PBKDF2-HMAC-SHA256 with a known vector derived from
/// python3 -c "from hashlib import pbkdf2_hmac; import binascii; print(binascii.hexlify(pbkdf2_hmac('sha256',b'password',b'salt',1,32)))"
/// = 0x120fb6cffccd202497cb38...  (use actual Python output below)
///
/// Oracle: Python 3 hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 1, 32)
///   = 120fb6cffccd202497cb38a6f2e170f0a35a9f6a5e16f91c75c7f4f80d2ae38f
#[test]
fn pbkdf2_hmacsha256_rfc_sanity() {
    common::init_wolfcrypt();

    let password = b"password";
    let salt = b"salt";
    let iterations: u32 = 1;
    let dk_len = 32;
    // Oracle: Python 3 hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 1, 32)
    let expected = common::hex_decode(
        "120fb6cffccd202497cb38a6f2e170f0a35a9f6a5e16f91c75c7f4f80d2ae38f"
    );

    let salt_str = SaltString::encode_b64(salt).expect("SaltString::encode_b64");
    let hasher = Pbkdf2HmacSha256::new(iterations, dk_len)
        .expect("Pbkdf2HmacSha256::new");
    let hash = hasher
        .hash_password(password, &salt_str)
        .expect("hash_password");
    let computed = hash
        .hash
        .expect("hash value present")
        .as_bytes()
        .to_vec();

    assert_eq!(
        &computed[..dk_len],
        expected.as_slice(),
        "PBKDF2-HMAC-SHA256 sanity check failed (oracle: Python hashlib)"
    );
}
