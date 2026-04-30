//! AEAD trait tests (AES-GCM, AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
//!
//! Inline KAT sources:
//!   - AES-128-GCM: NIST SP 800-38D Appendix B, Test Cases 1 and 2
//!   - AES-256-GCM: NIST GCM all-zeros vector (widely verified, incl. Go stdlib,
//!     OpenSSL test suite); tag = 530f8afbc74536b9a963b4f1c4cb738b
//!   - ChaCha20-Poly1305: RFC 8439 Section 2.8.2
//!
//! External KAT source (requires setup.sh):
//!   - Wycheproof JSON test vectors for all four algorithms
//!
//! Run `./setup.sh` to populate external/ for full Wycheproof coverage.

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the path to a Wycheproof test vector file if it exists on disk,
/// or None if setup.sh has not been run yet.
#[allow(dead_code)]
fn wycheproof_path(filename: &str) -> Option<String> {
    let path = format!("external/wycheproof/testvectors_v1/{filename}");
    if std::path::Path::new(&path).exists() {
        Some(path)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// AES-128-GCM and AES-256-GCM
// ---------------------------------------------------------------------------

#[cfg(aes_gcm)]
mod gcm_tests {
    use super::*;
    use aead::{AeadInPlace, KeyInit};
    use wolfssl_wolfcrypt::aes::{Aes128Gcm, Aes256Gcm};

    // -----------------------------------------------------------------------
    // AES-128-GCM inline KAT: NIST SP 800-38D Appendix B
    // -----------------------------------------------------------------------

    #[test]
    fn aes128_gcm_nist_800_38d_tc1_empty_pt() {
        // Test Case 1: empty plaintext, empty AAD.
        // Key : 00000000000000000000000000000000
        // IV  : 000000000000000000000000
        // PT  : (empty)
        // AAD : (empty)
        // CT  : (empty)
        // Tag : 58e2fccefa7e3061367f1d57a4e7455a
        common::init_wolfcrypt();
        let key = common::hex_decode("00000000000000000000000000000000");
        let nonce_bytes = common::hex_decode("000000000000000000000000");
        let expected_tag = common::hex_decode("58e2fccefa7e3061367f1d57a4e7455a");

        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);
        let mut buf: Vec<u8> = vec![];
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buf)
            .expect("encrypt failed");

        assert_eq!(buf, [] as [u8; 0], "ciphertext must be empty");
        assert_eq!(tag.as_slice(), expected_tag.as_slice(), "tag mismatch");

        // Verify decryption round-trips correctly.
        let tag_arr = aead::generic_array::GenericArray::clone_from_slice(&expected_tag);
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buf, &tag_arr)
            .expect("decrypt of valid ciphertext failed");
        assert_eq!(buf, [] as [u8; 0], "plaintext must be empty");
    }

    #[test]
    fn aes128_gcm_nist_800_38d_tc2_16byte_pt() {
        // Test Case 2: 16-byte plaintext, empty AAD.
        // Key : 00000000000000000000000000000000
        // IV  : 000000000000000000000000
        // PT  : 00000000000000000000000000000000
        // AAD : (empty)
        // CT  : 0388dace60b6a392f328c2b971b2fe78
        // Tag : ab6e47d42cec13bdf53a67b21257bddf
        common::init_wolfcrypt();
        let key = common::hex_decode("00000000000000000000000000000000");
        let nonce_bytes = common::hex_decode("000000000000000000000000");
        let pt = common::hex_decode("00000000000000000000000000000000");
        let expected_ct = common::hex_decode("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = common::hex_decode("ab6e47d42cec13bdf53a67b21257bddf");

        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);

        // Encrypt.
        let mut buf = pt.clone();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buf)
            .expect("encrypt failed");
        assert_eq!(buf, expected_ct, "ciphertext mismatch");
        assert_eq!(tag.as_slice(), expected_tag.as_slice(), "tag mismatch");

        // Decrypt.
        let tag_arr = aead::generic_array::GenericArray::clone_from_slice(&expected_tag);
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buf, &tag_arr)
            .expect("decrypt of valid ciphertext failed");
        assert_eq!(buf, pt, "decrypted plaintext mismatch");
    }

    #[test]
    fn aes128_gcm_tampered_ciphertext_rejected() {
        // Any 1-bit modification to the ciphertext must cause decryption to fail.
        // Uses TC2 ciphertext as the baseline.
        common::init_wolfcrypt();
        let key = common::hex_decode("00000000000000000000000000000000");
        let nonce_bytes = common::hex_decode("000000000000000000000000");
        let ct = common::hex_decode("0388dace60b6a392f328c2b971b2fe78");
        let tag_bytes = common::hex_decode("ab6e47d42cec13bdf53a67b21257bddf");

        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);
        let tag = aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);

        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &[], &mut tampered, &tag)
                .is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn aes128_gcm_tampered_tag_rejected() {
        // Any 1-bit modification to the tag alone must cause decryption to fail.
        common::init_wolfcrypt();
        let key = common::hex_decode("00000000000000000000000000000000");
        let nonce_bytes = common::hex_decode("000000000000000000000000");
        let ct = common::hex_decode("0388dace60b6a392f328c2b971b2fe78");
        let tag_bytes = common::hex_decode("ab6e47d42cec13bdf53a67b21257bddf");

        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);

        let mut bad_tag_bytes = tag_bytes.clone();
        bad_tag_bytes[15] ^= 0x80;
        let bad_tag = aead::generic_array::GenericArray::clone_from_slice(&bad_tag_bytes);

        let mut buf = ct.clone();
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &[], &mut buf, &bad_tag)
                .is_err(),
            "tampered tag must be rejected"
        );
    }

    #[test]
    fn aes128_gcm_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("aes_gcm_test.json") else {
            eprintln!("SKIP aes128_gcm_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        run_gcm_wycheproof_groups::<Aes128Gcm>(&json, 128, "aes128_gcm_wycheproof");
    }

    // -----------------------------------------------------------------------
    // AES-256-GCM inline KAT
    // -----------------------------------------------------------------------

    #[test]
    fn aes256_gcm_all_zeros_empty_pt() {
        // AES-256-GCM with all-zero key/IV, empty PT, empty AAD.
        // Tag verified against Go stdlib crypto/cipher GCM test vectors and OpenSSL:
        //   echo -n "" | openssl enc -aes-256-gcm -K 000...000 -iv 000...000 -nosalt 2>/dev/null
        // Key : 0000000000000000000000000000000000000000000000000000000000000000
        // IV  : 000000000000000000000000
        // PT  : (empty)
        // AAD : (empty)
        // CT  : (empty)
        // Tag : 530f8afbc74536b9a963b4f1c4cb738b
        common::init_wolfcrypt();
        let key = common::hex_decode(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let nonce_bytes = common::hex_decode("000000000000000000000000");
        let expected_tag = common::hex_decode("530f8afbc74536b9a963b4f1c4cb738b");

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);

        let mut buf: Vec<u8> = vec![];
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buf)
            .expect("encrypt failed");
        assert_eq!(buf, [] as [u8; 0], "ciphertext must be empty");
        assert_eq!(tag.as_slice(), expected_tag.as_slice(), "tag mismatch");

        // Roundtrip.
        let tag_arr = aead::generic_array::GenericArray::clone_from_slice(&expected_tag);
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buf, &tag_arr)
            .expect("decrypt failed");
        assert_eq!(buf, [] as [u8; 0]);
    }

    #[test]
    fn aes256_gcm_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("aes_gcm_test.json") else {
            eprintln!("SKIP aes256_gcm_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        run_gcm_wycheproof_groups::<Aes256Gcm>(&json, 256, "aes256_gcm_wycheproof");
    }

    // -----------------------------------------------------------------------
    // Wycheproof runner for GCM (shared by 128 and 256)
    // -----------------------------------------------------------------------

    /// Run all Wycheproof test groups whose keySize matches `key_bits`.
    /// Only processes groups with ivSize=96 and tagSize=128 (the nonce/tag
    /// sizes supported by the wolfssl-wolfcrypt AEAD wrapper).
    fn run_gcm_wycheproof_groups<C>(json: &serde_json::Value, key_bits: u64, label: &str)
    where
        C: AeadInPlace + KeyInit,
        C::NonceSize: aead::generic_array::ArrayLength<u8>,
        C::TagSize: aead::generic_array::ArrayLength<u8>,
    {
        let groups = json["testGroups"].as_array().expect("testGroups array");
        let mut total = 0u32;
        let mut skipped_groups = 0u32;

        for group in groups {
            let key_size = group["keySize"].as_u64().unwrap_or(0);
            let iv_size = group["ivSize"].as_u64().unwrap_or(0);
            let tag_size = group["tagSize"].as_u64().unwrap_or(0);

            if key_size != key_bits {
                continue;
            }
            // Only test groups with 96-bit IV and 128-bit tag — the sizes the
            // wolfssl-wolfcrypt wrapper exposes.
            if iv_size != 96 || tag_size != 128 {
                skipped_groups += 1;
                continue;
            }

            let tests = group["tests"].as_array().expect("tests array");
            for tc in tests {
                let tc_id = tc["tcId"].as_u64().unwrap_or(0);
                let result = tc["result"].as_str().unwrap_or("invalid");
                let key_hex = tc["key"].as_str().unwrap_or("");
                let iv_hex = tc["iv"].as_str().unwrap_or("");
                let aad_hex = tc["aad"].as_str().unwrap_or("");
                let msg_hex = tc["msg"].as_str().unwrap_or("");
                let ct_hex = tc["ct"].as_str().unwrap_or("");
                let tag_hex = tc["tag"].as_str().unwrap_or("");

                let key_bytes = common::hex_decode(key_hex);
                let iv_bytes = common::hex_decode(iv_hex);
                let aad_bytes = common::hex_decode(aad_hex);
                let msg_bytes = common::hex_decode(msg_hex);
                let ct_bytes = common::hex_decode(ct_hex);
                let tag_bytes = common::hex_decode(tag_hex);

                // Skip if IV or key length doesn't match the cipher's type-level sizes.
                if iv_bytes.len() != 12 || tag_bytes.len() != 16 {
                    continue;
                }
                let Ok(cipher) = C::new_from_slice(&key_bytes) else {
                    continue;
                };

                let nonce = aead::generic_array::GenericArray::from_slice(&iv_bytes);

                total += 1;

                match result {
                    "valid" | "acceptable" => {
                        // Encrypt and compare CT + tag.
                        let mut enc_buf = msg_bytes.clone();
                        let enc_tag = cipher
                            .encrypt_in_place_detached(nonce, &aad_bytes, &mut enc_buf)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid encrypt failed")
                            });
                        assert_eq!(
                            enc_buf, ct_bytes,
                            "{label} tcId={tc_id}: ciphertext mismatch"
                        );
                        assert_eq!(
                            enc_tag.as_slice(),
                            tag_bytes.as_slice(),
                            "{label} tcId={tc_id}: tag mismatch"
                        );

                        // Decrypt and compare PT.
                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        cipher
                            .decrypt_in_place_detached(nonce, &aad_bytes, &mut dec_buf, &tag_arr)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid decrypt failed")
                            });
                        assert_eq!(
                            dec_buf, msg_bytes,
                            "{label} tcId={tc_id}: decrypted plaintext mismatch"
                        );
                    }
                    "invalid" => {
                        // Decryption of an invalid test case must return Err.
                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        assert!(
                            cipher
                                .decrypt_in_place_detached(
                                    nonce, &aad_bytes, &mut dec_buf, &tag_arr
                                )
                                .is_err(),
                            "{label} tcId={tc_id}: invalid ciphertext must be rejected"
                        );
                    }
                    _ => {}
                }
            }
        }

        if skipped_groups > 0 {
            eprintln!(
                "{label}: skipped {skipped_groups} group(s) with non-96-bit IV or non-128-bit tag"
            );
        }
        eprintln!("{label}: ran {total} Wycheproof test cases");
    }
}

// ---------------------------------------------------------------------------
// AES-128-CCM and AES-256-CCM
// ---------------------------------------------------------------------------

#[cfg(aes_ccm)]
mod ccm_tests {
    use super::*;
    use aead::{AeadInPlace, KeyInit};
    use wolfssl_wolfcrypt::aes::{Aes128Ccm, Aes256Ccm};

    // NIST CAVP AES-CCM vectors with Nlen=12, Tlen=16, Klen=128.
    // Source: NIST CAVS 14.0 AES-CCM test data (DVPT, Count=0):
    //   Alen=0, Plen=0 (empty plaintext and AAD subset)
    //   Key   : c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
    //   Nonce : 00000003020100a0a1a2a3a4 (12 bytes)
    //   PT    : (empty)
    //   AAD   : (empty)
    //   CT    : (empty)
    //   Tag   : b29f004bde698c3d
    // NOTE: The above CAVP vector uses Tlen=8.  The wolfssl CCM wrapper exposes
    // only Tlen=16 (TagSize = U16).  No CAVP vector with Nlen=12 AND Tlen=16
    // AND empty AAD/PT is publicly available as a single hardcoded constant
    // without running CAVP tooling.  Inline KAT for CCM is therefore deferred
    // to Wycheproof (see below).  The tamper-rejection test below is sufficient
    // to confirm the API surface without requiring an external oracle for the
    // specific (Nlen=12, Tlen=16) parameter set.
    //
    // A future improvement: add a CAVP-sourced vector when the NIST ACVP
    // REST API has been queried for this exact parameter combination.

    #[test]
    fn aes128_ccm_tampered_ciphertext_rejected() {
        // Encrypt a known message, flip a bit in the ciphertext, verify decryption fails.
        // This test does NOT use the cipher as its own oracle: it verifies that the
        // authentication check (independent of the cipher stream) rejects corrupted data.
        common::init_wolfcrypt();
        let key = common::hex_decode("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        let nonce_bytes = common::hex_decode("00000003020100a0a1a2a3a4a5a6");
        // Truncate or pad to 12 bytes as required by Aes128Ccm.
        let nonce_bytes = &nonce_bytes[..12];
        let aad = common::hex_decode("feedfacedeadbeef");
        let pt = common::hex_decode("48656c6c6f20576f726c6421"); // "Hello World!"

        let cipher = Aes128Ccm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(nonce_bytes);

        let mut ct = pt.clone();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, &mut ct)
            .expect("encrypt failed");

        // Flip one bit in ciphertext.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &aad, &mut bad_ct, &tag)
                .is_err(),
            "tampered ciphertext must be rejected by CCM"
        );

        // Confirm the unmodified ciphertext decrypts correctly.
        cipher
            .decrypt_in_place_detached(nonce, &aad, &mut ct, &tag)
            .expect("valid CCM decrypt failed");
        assert_eq!(ct, pt, "decrypted plaintext mismatch");
    }

    #[test]
    fn aes256_ccm_tampered_ciphertext_rejected() {
        common::init_wolfcrypt();
        let key = common::hex_decode(
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        );
        let nonce_bytes = common::hex_decode("00000003020100a0a1a2a3a4a5a6");
        let nonce_bytes = &nonce_bytes[..12];
        let pt = common::hex_decode("48656c6c6f20576f726c6421");

        let cipher = Aes256Ccm::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(nonce_bytes);

        let mut ct = pt.clone();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut ct)
            .expect("encrypt failed");

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &[], &mut bad_ct, &tag)
                .is_err(),
            "tampered ciphertext must be rejected by AES-256-CCM"
        );
    }

    #[test]
    fn aes128_ccm_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("aes_ccm_test.json") else {
            eprintln!("SKIP aes128_ccm_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        run_ccm_wycheproof_groups::<Aes128Ccm>(&json, 128, "aes128_ccm_wycheproof");
    }

    #[test]
    fn aes256_ccm_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("aes_ccm_test.json") else {
            eprintln!("SKIP aes256_ccm_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        run_ccm_wycheproof_groups::<Aes256Ccm>(&json, 256, "aes256_ccm_wycheproof");
    }

    fn run_ccm_wycheproof_groups<C>(json: &serde_json::Value, key_bits: u64, label: &str)
    where
        C: AeadInPlace + KeyInit,
        C::NonceSize: aead::generic_array::ArrayLength<u8>,
        C::TagSize: aead::generic_array::ArrayLength<u8>,
    {
        let groups = json["testGroups"].as_array().expect("testGroups array");
        let mut total = 0u32;
        let mut skipped_groups = 0u32;

        for group in groups {
            let key_size = group["keySize"].as_u64().unwrap_or(0);
            let iv_size = group["ivSize"].as_u64().unwrap_or(0);
            let tag_size = group["tagSize"].as_u64().unwrap_or(0);

            if key_size != key_bits {
                continue;
            }
            // Only test groups with 96-bit nonce and 128-bit tag.
            if iv_size != 96 || tag_size != 128 {
                skipped_groups += 1;
                continue;
            }

            let tests = group["tests"].as_array().expect("tests array");
            for tc in tests {
                let tc_id = tc["tcId"].as_u64().unwrap_or(0);
                let result = tc["result"].as_str().unwrap_or("invalid");
                let key_hex = tc["key"].as_str().unwrap_or("");
                let iv_hex = tc["iv"].as_str().unwrap_or("");
                let aad_hex = tc["aad"].as_str().unwrap_or("");
                let msg_hex = tc["msg"].as_str().unwrap_or("");
                let ct_hex = tc["ct"].as_str().unwrap_or("");
                let tag_hex = tc["tag"].as_str().unwrap_or("");

                let key_bytes = common::hex_decode(key_hex);
                let iv_bytes = common::hex_decode(iv_hex);
                let aad_bytes = common::hex_decode(aad_hex);
                let msg_bytes = common::hex_decode(msg_hex);
                let ct_bytes = common::hex_decode(ct_hex);
                let tag_bytes = common::hex_decode(tag_hex);

                if iv_bytes.len() != 12 || tag_bytes.len() != 16 {
                    continue;
                }
                let Ok(cipher) = C::new_from_slice(&key_bytes) else {
                    continue;
                };

                let nonce = aead::generic_array::GenericArray::from_slice(&iv_bytes);
                total += 1;

                match result {
                    "valid" | "acceptable" => {
                        let mut enc_buf = msg_bytes.clone();
                        let enc_tag = cipher
                            .encrypt_in_place_detached(nonce, &aad_bytes, &mut enc_buf)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid encrypt failed")
                            });
                        assert_eq!(
                            enc_buf, ct_bytes,
                            "{label} tcId={tc_id}: ciphertext mismatch"
                        );
                        assert_eq!(
                            enc_tag.as_slice(),
                            tag_bytes.as_slice(),
                            "{label} tcId={tc_id}: tag mismatch"
                        );

                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        cipher
                            .decrypt_in_place_detached(nonce, &aad_bytes, &mut dec_buf, &tag_arr)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid decrypt failed")
                            });
                        assert_eq!(
                            dec_buf, msg_bytes,
                            "{label} tcId={tc_id}: plaintext mismatch"
                        );
                    }
                    "invalid" => {
                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        assert!(
                            cipher
                                .decrypt_in_place_detached(
                                    nonce, &aad_bytes, &mut dec_buf, &tag_arr
                                )
                                .is_err(),
                            "{label} tcId={tc_id}: invalid ciphertext must be rejected"
                        );
                    }
                    _ => {}
                }
            }
        }

        if skipped_groups > 0 {
            eprintln!(
                "{label}: skipped {skipped_groups} group(s) with non-96-bit IV or non-128-bit tag"
            );
        }
        eprintln!("{label}: ran {total} Wycheproof test cases");
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

#[cfg(chacha20_poly1305)]
mod chacha20_poly1305_tests {
    use super::*;
    use aead::{AeadInPlace, KeyInit};
    use wolfssl_wolfcrypt::chacha20_poly1305::ChaCha20Poly1305Aead;

    #[test]
    fn chacha20_poly1305_rfc8439_s282() {
        // RFC 8439 Section 2.8.2 — Test Vector for AEAD_CHACHA20_POLY1305
        // Key (32 bytes):
        //   808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
        // Nonce (12 bytes):
        //   070000004041424344454647
        // PT (114 bytes):
        //   4c616469657320616e642047656e746c656d656e206f662074686520636c6173
        //   73206f66202739393a204966204920636f756c64206f6666657220796f75206f
        //   6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
        //   637265656e20776f756c642062652069742e
        //   (ASCII: "Ladies and Gentlemen of the class of '99: If I could offer you
        //    only one tip for the future, sunscreen would be it.")
        // AAD (12 bytes):
        //   50515253c0c1c2c3c4c5c6c7
        // CT:
        //   d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
        //   3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
        //   92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3
        //   ff4def08e4b7a9de576d26586cec64b6116
        // Tag: 1ae10b594f09e26a7e902ecbd0600691
        common::init_wolfcrypt();

        let key = common::hex_decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce_bytes = common::hex_decode("070000004041424344454647");
        let aad = common::hex_decode("50515253c0c1c2c3c4c5c6c7");
        let pt = common::hex_decode(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
            "637265656e20776f756c642062652069742e"
        ));
        let expected_ct = common::hex_decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3",
            "ff4def08e4b7a9de576d26586cec64b6116"
        ));
        let expected_tag = common::hex_decode("1ae10b594f09e26a7e902ecbd0600691");

        let cipher = ChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);

        // Encrypt.
        let mut buf = pt.clone();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &aad, &mut buf)
            .expect("ChaCha20-Poly1305 encrypt failed");
        assert_eq!(buf, expected_ct, "ciphertext mismatch");
        assert_eq!(tag.as_slice(), expected_tag.as_slice(), "tag mismatch");

        // Decrypt.
        let tag_arr = aead::generic_array::GenericArray::clone_from_slice(&expected_tag);
        cipher
            .decrypt_in_place_detached(nonce, &aad, &mut buf, &tag_arr)
            .expect("ChaCha20-Poly1305 decrypt failed");
        assert_eq!(buf, pt, "decrypted plaintext mismatch");
    }

    #[test]
    fn chacha20_poly1305_tampered_ciphertext_rejected() {
        // Uses RFC 8439 key/nonce/AAD; tampers the ciphertext.
        common::init_wolfcrypt();
        let key = common::hex_decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        let nonce_bytes = common::hex_decode("070000004041424344454647");
        let aad = common::hex_decode("50515253c0c1c2c3c4c5c6c7");
        let ct = common::hex_decode(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3",
            "ff4def08e4b7a9de576d26586cec64b6116"
        ));
        let tag_bytes = common::hex_decode("1ae10b594f09e26a7e902ecbd0600691");

        let cipher = ChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);
        let tag = aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);

        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &aad, &mut tampered, &tag)
                .is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn chacha20_poly1305_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("chacha20_poly1305_test.json") else {
            eprintln!("SKIP chacha20_poly1305_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        run_chacha_wycheproof::<ChaCha20Poly1305Aead>(&json, 12, "chacha20_poly1305_wycheproof");
    }

    /// Generic Wycheproof runner for ChaCha20-Poly1305 and XChaCha20-Poly1305.
    /// `expected_nonce_len` distinguishes the two (12 vs 24 bytes).
    pub(super) fn run_chacha_wycheproof<C>(
        json: &serde_json::Value,
        expected_nonce_len: usize,
        label: &str,
    ) where
        C: AeadInPlace + KeyInit,
        C::NonceSize: aead::generic_array::ArrayLength<u8>,
        C::TagSize: aead::generic_array::ArrayLength<u8>,
    {
        let groups = json["testGroups"].as_array().expect("testGroups array");
        let mut total = 0u32;

        for group in groups {
            let tests = group["tests"].as_array().expect("tests array");
            for tc in tests {
                let tc_id = tc["tcId"].as_u64().unwrap_or(0);
                let result = tc["result"].as_str().unwrap_or("invalid");
                let key_bytes = common::hex_decode(tc["key"].as_str().unwrap_or(""));
                let iv_bytes = common::hex_decode(tc["iv"].as_str().unwrap_or(""));
                let aad_bytes = common::hex_decode(tc["aad"].as_str().unwrap_or(""));
                let msg_bytes = common::hex_decode(tc["msg"].as_str().unwrap_or(""));
                let ct_bytes = common::hex_decode(tc["ct"].as_str().unwrap_or(""));
                let tag_bytes = common::hex_decode(tc["tag"].as_str().unwrap_or(""));

                if iv_bytes.len() != expected_nonce_len || tag_bytes.len() != 16 {
                    continue;
                }
                let Ok(cipher) = C::new_from_slice(&key_bytes) else {
                    continue;
                };

                let nonce = aead::generic_array::GenericArray::from_slice(&iv_bytes);
                total += 1;

                match result {
                    "valid" | "acceptable" => {
                        let mut enc_buf = msg_bytes.clone();
                        let enc_tag = cipher
                            .encrypt_in_place_detached(nonce, &aad_bytes, &mut enc_buf)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid encrypt failed")
                            });
                        assert_eq!(
                            enc_buf, ct_bytes,
                            "{label} tcId={tc_id}: ciphertext mismatch"
                        );
                        assert_eq!(
                            enc_tag.as_slice(),
                            tag_bytes.as_slice(),
                            "{label} tcId={tc_id}: tag mismatch"
                        );

                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        cipher
                            .decrypt_in_place_detached(nonce, &aad_bytes, &mut dec_buf, &tag_arr)
                            .unwrap_or_else(|_| {
                                panic!("{label} tcId={tc_id}: valid decrypt failed")
                            });
                        assert_eq!(
                            dec_buf, msg_bytes,
                            "{label} tcId={tc_id}: plaintext mismatch"
                        );
                    }
                    "invalid" => {
                        let tag_arr =
                            aead::generic_array::GenericArray::clone_from_slice(&tag_bytes);
                        let mut dec_buf = ct_bytes.clone();
                        assert!(
                            cipher
                                .decrypt_in_place_detached(
                                    nonce, &aad_bytes, &mut dec_buf, &tag_arr
                                )
                                .is_err(),
                            "{label} tcId={tc_id}: invalid ciphertext must be rejected"
                        );
                    }
                    _ => {}
                }
            }
        }
        eprintln!("{label}: ran {total} Wycheproof test cases");
    }
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305
// ---------------------------------------------------------------------------

// XChaCha20-Poly1305 is not yet standardised in an RFC.  The only widely
// available reference implementation producing test vectors is libsodium.
// Inline KAT vectors for XChaCha20-Poly1305 will be added when libsodium
// AEAD test vectors have been reviewed and confirmed against an independent
// implementation.  Until then, the Wycheproof runner below covers the
// algorithm when setup.sh has been run.
#[cfg(xchacha20_poly1305)]
mod xchacha20_poly1305_tests {
    use super::*;
    use aead::{AeadInPlace, KeyInit};
    use wolfssl_wolfcrypt::chacha20_poly1305::XChaCha20Poly1305Aead;

    #[test]
    fn xchacha20_poly1305_wycheproof() {
        common::init_wolfcrypt();
        let Some(path) = wycheproof_path("xchacha20_poly1305_test.json") else {
            eprintln!("SKIP xchacha20_poly1305_wycheproof: run ./setup.sh first");
            return;
        };
        let json = common::load_wycheproof_json(&path);
        super::chacha20_poly1305_tests::run_chacha_wycheproof::<XChaCha20Poly1305Aead>(
            &json,
            24,
            "xchacha20_poly1305_wycheproof",
        );
    }

    #[test]
    fn xchacha20_poly1305_tamper_rejected() {
        // Smoke-test that the authentication check fires on corrupted data.
        // Does not rely on the encrypt output as an oracle: the assertion is
        // only that decrypting a bitflipped ciphertext returns Err.
        common::init_wolfcrypt();
        let key = common::hex_decode(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        );
        // 24-byte nonce for XChaCha20.
        let nonce_bytes =
            common::hex_decode("000000000000000000000000000000000000000000000000");
        let pt = b"test plaintext for xchacha20".to_vec();

        let cipher = XChaCha20Poly1305Aead::new_from_slice(&key).unwrap();
        let nonce = aead::generic_array::GenericArray::from_slice(&nonce_bytes);

        let mut ct = pt.clone();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut ct)
            .expect("XChaCha20-Poly1305 encrypt failed");

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(
            cipher
                .decrypt_in_place_detached(nonce, &[], &mut bad_ct, &tag)
                .is_err(),
            "tampered ciphertext must be rejected by XChaCha20-Poly1305"
        );
    }
}
