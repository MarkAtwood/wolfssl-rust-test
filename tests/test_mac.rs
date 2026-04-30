//! MAC trait tests (HMAC and CMAC via digest::Mac).
//! Requires wolfssl-wolfcrypt `mac` feature (PR #10305, cmac_mac.rs + hmac_mac.rs).
//! Will not compile until PR is merged and Cargo.toml updated.
//!
//! Expected compile errors until PR #10305 lands:
//!   - `wolfssl_wolfcrypt::cmac_mac` module not found
//!   - `wolfssl_wolfcrypt::hmac_mac` module not found
//!   - `digest` crate not found (must be added to Cargo.toml as dev-dependency)
//!   - `digest::Mac` trait not in scope

mod common;

// These imports require PR #10305 (cmac_mac.rs + hmac_mac.rs) and
// the `digest` dev-dependency in Cargo.toml.
use wolfssl_wolfcrypt::cmac_mac::CmacAes128;
use wolfssl_wolfcrypt::cmac_mac::CmacAes192;
use wolfssl_wolfcrypt::cmac_mac::CmacAes256;
use wolfssl_wolfcrypt::hmac_mac::HmacSha256;
use digest::Mac;

// ── NIST SP 800-38B CMAC vectors ────────────────────────────────────────────

#[path = "../testvectors/nist/cmac_38b.rs"]
mod cmac_38b;

/// Run one CMAC generate+verify pair against the digest::Mac trait.
///
/// `M` is the concrete Mac implementor (CmacAes128 / CmacAes192 / CmacAes256).
/// `KEY_HEX`, `MSG_HEX`, and `TAG_HEX` are hex-encoded NIST test vector strings.
fn cmac_kat<M>(label: &str, key_hex: &str, msg_hex: &str, tag_hex: &str)
where
    M: Mac + digest::KeyInit,
{
    common::init_wolfcrypt();
    let key = common::hex_decode(key_hex);
    let msg = common::hex_decode(msg_hex);
    let expected_tag = common::hex_decode(tag_hex);

    // Generate path
    let mut mac = M::new_from_slice(&key)
        .unwrap_or_else(|e| panic!("{label}: new_from_slice failed: {e}"));
    mac.update(&msg);
    let computed = mac.finalize().into_bytes();
    assert_eq!(
        computed.as_slice(),
        expected_tag.as_slice(),
        "{label}: CMAC tag mismatch"
    );

    // Verify path (success)
    let mut mac = M::new_from_slice(&key)
        .unwrap_or_else(|e| panic!("{label}: new_from_slice (verify) failed: {e}"));
    mac.update(&msg);
    mac.verify_slice(&expected_tag)
        .unwrap_or_else(|e| panic!("{label}: verify_slice rejected valid tag: {e}"));
}

// ── AES-128 (D.1) ───────────────────────────────────────────────────────────

#[test]
fn cmac_aes128_ex1_empty() {
    cmac_kat::<CmacAes128>(
        "AES-128 ex1 (Mlen=0)",
        aes128::KEY,
        aes128::ex1::MSG,
        aes128::ex1::TAG,
    );
}

#[test]
fn cmac_aes128_ex2_one_block() {
    cmac_kat::<CmacAes128>(
        "AES-128 ex2 (Mlen=16)",
        aes128::KEY,
        aes128::ex2::MSG,
        aes128::ex2::TAG,
    );
}

#[test]
fn cmac_aes128_ex3_partial() {
    cmac_kat::<CmacAes128>(
        "AES-128 ex3 (Mlen=40)",
        aes128::KEY,
        aes128::ex3::MSG,
        aes128::ex3::TAG,
    );
}

#[test]
fn cmac_aes128_ex4_four_blocks() {
    cmac_kat::<CmacAes128>(
        "AES-128 ex4 (Mlen=64)",
        aes128::KEY,
        aes128::ex4::MSG,
        aes128::ex4::TAG,
    );
}

// ── AES-192 (D.2) ───────────────────────────────────────────────────────────

#[test]
fn cmac_aes192_ex1_empty() {
    cmac_kat::<CmacAes192>(
        "AES-192 ex1 (Mlen=0)",
        aes192::KEY,
        aes192::ex1::MSG,
        aes192::ex1::TAG,
    );
}

#[test]
fn cmac_aes192_ex2_one_block() {
    cmac_kat::<CmacAes192>(
        "AES-192 ex2 (Mlen=16)",
        aes192::KEY,
        aes192::ex2::MSG,
        aes192::ex2::TAG,
    );
}

#[test]
fn cmac_aes192_ex3_partial() {
    cmac_kat::<CmacAes192>(
        "AES-192 ex3 (Mlen=40)",
        aes192::KEY,
        aes192::ex3::MSG,
        aes192::ex3::TAG,
    );
}

#[test]
fn cmac_aes192_ex4_four_blocks() {
    cmac_kat::<CmacAes192>(
        "AES-192 ex4 (Mlen=64)",
        aes192::KEY,
        aes192::ex4::MSG,
        aes192::ex4::TAG,
    );
}

// ── AES-256 (D.3) ───────────────────────────────────────────────────────────

#[test]
fn cmac_aes256_ex1_empty() {
    cmac_kat::<CmacAes256>(
        "AES-256 ex1 (Mlen=0)",
        aes256::KEY,
        aes256::ex1::MSG,
        aes256::ex1::TAG,
    );
}

#[test]
fn cmac_aes256_ex2_one_block() {
    cmac_kat::<CmacAes256>(
        "AES-256 ex2 (Mlen=16)",
        aes256::KEY,
        aes256::ex2::MSG,
        aes256::ex2::TAG,
    );
}

#[test]
fn cmac_aes256_ex3_partial() {
    cmac_kat::<CmacAes256>(
        "AES-256 ex3 (Mlen=40)",
        aes256::KEY,
        aes256::ex3::MSG,
        aes256::ex3::TAG,
    );
}

#[test]
fn cmac_aes256_ex4_four_blocks() {
    cmac_kat::<CmacAes256>(
        "AES-256 ex4 (Mlen=64)",
        aes256::KEY,
        aes256::ex4::MSG,
        aes256::ex4::TAG,
    );
}

// ── CMAC negative: wrong tag returns Err ────────────────────────────────────

#[test]
fn cmac_aes128_wrong_tag_rejected() {
    common::init_wolfcrypt();
    let key = common::hex_decode(aes128::KEY);
    let msg = common::hex_decode(aes128::ex2::MSG);
    let mut bad_tag = common::hex_decode(aes128::ex2::TAG);
    // Flip the last byte so the tag is wrong.
    *bad_tag.last_mut().unwrap() ^= 0xff;

    let mut mac = CmacAes128::new_from_slice(&key)
        .expect("new_from_slice failed");
    mac.update(&msg);
    assert!(
        mac.verify_slice(&bad_tag).is_err(),
        "verify_slice must return Err for a wrong tag"
    );
}

// ── HMAC-SHA256 Wycheproof vectors ──────────────────────────────────────────

const WYCHEPROOF_HMAC_SHA256: &str =
    "external/wycheproof/testvectors_v1/hmac_sha256_test.json";

/// Run Wycheproof HMAC-SHA256 test vectors if the file is present.
/// Skip (with eprintln) if the file is absent — run ./setup.sh to populate it.
#[test]
fn hmac_sha256_wycheproof() {
    common::init_wolfcrypt();

    if !std::path::Path::new(WYCHEPROOF_HMAC_SHA256).exists() {
        eprintln!(
            "SKIP hmac_sha256_wycheproof: {} not found; run ./setup.sh",
            WYCHEPROOF_HMAC_SHA256
        );
        return;
    }

    let content = std::fs::read_to_string(WYCHEPROOF_HMAC_SHA256)
        .expect("failed to read Wycheproof HMAC-SHA256 file");
    let root: serde_json::Value =
        serde_json::from_str(&content).expect("invalid JSON in Wycheproof file");

    let mut passed = 0usize;
    let mut skipped = 0usize;

    for group in root["testGroups"].as_array().expect("testGroups") {
        let key_size = group["keySize"].as_u64().unwrap_or(0);
        // Only run 256-bit (32-byte) key groups; other key sizes are valid but
        // HmacSha256 as a fixed-key-size type may reject them.
        if key_size != 256 {
            skipped += group["tests"]
                .as_array()
                .map(|v| v.len())
                .unwrap_or(0);
            continue;
        }

        for tc in group["tests"].as_array().expect("tests") {
            let tc_id = tc["tcId"].as_u64().unwrap_or(0);
            let result = tc["result"].as_str().unwrap_or("invalid");
            let key_hex = tc["key"].as_str().expect("key");
            let msg_hex = tc["msg"].as_str().expect("msg");
            let tag_hex = tc["tag"].as_str().expect("tag");

            let key = common::hex_decode(key_hex);
            let msg = common::hex_decode(msg_hex);
            let tag = common::hex_decode(tag_hex);

            let mac_result = HmacSha256::new_from_slice(&key)
                .map(|mut m| { m.update(&msg); m.finalize().into_bytes() });

            match result {
                "valid" => {
                    let computed = mac_result
                        .unwrap_or_else(|e| panic!("tc#{tc_id}: HMAC init failed: {e}"));
                    assert_eq!(
                        computed.as_slice(),
                        tag.as_slice(),
                        "tc#{tc_id}: HMAC-SHA256 tag mismatch"
                    );
                    passed += 1;
                }
                "invalid" => {
                    // A tag that doesn't match should fail verify_slice.
                    // We compute the real tag and check it differs from the vector tag.
                    if let Ok(computed) = mac_result {
                        assert_ne!(
                            computed.as_slice(),
                            tag.as_slice(),
                            "tc#{tc_id}: invalid vector produced matching tag"
                        );
                    }
                    passed += 1;
                }
                _ => {
                    skipped += 1;
                }
            }
        }
    }

    eprintln!(
        "hmac_sha256_wycheproof: {passed} cases checked, {skipped} skipped"
    );
    assert!(passed > 0, "no test cases were executed");
}

// ── HMAC negative: wrong tag returns Err ────────────────────────────────────

#[test]
fn hmac_sha256_wrong_tag_rejected() {
    common::init_wolfcrypt();
    let key = [0x42u8; 32];
    let msg = b"hello world";

    // Compute the correct tag.
    let mut mac = HmacSha256::new_from_slice(&key).expect("new_from_slice");
    mac.update(msg);
    let correct_tag = mac.finalize().into_bytes();

    // Flip one byte and verify it is rejected.
    let mut bad_tag = correct_tag.to_vec();
    *bad_tag.last_mut().unwrap() ^= 0x01;

    let mut mac = HmacSha256::new_from_slice(&key).expect("new_from_slice");
    mac.update(msg);
    assert!(
        mac.verify_slice(&bad_tag).is_err(),
        "verify_slice must return Err for a wrong HMAC tag"
    );
}
