//! AES cipher trait tests against NIST SP 800-38A Appendix F vectors.
//!
//! Requires wolfssl built with --enable-all (for all modes to be available).
//! Run setup.sh before running tests (for Wycheproof vectors in later tests).

mod common;

#[path = "../testvectors/nist/aes_38a.rs"]
mod aes_38a;

// ---------------------------------------------------------------------------
// ECB — NIST SP 800-38A Appendix F.1
// ---------------------------------------------------------------------------

#[cfg(aes_ecb)]
mod ecb_tests {
    use super::{aes_38a, common};
    use cipher::{BlockModeDecrypt, BlockModeEncrypt, InOutBuf, KeyInit};
    use wolfssl_wolfcrypt::aes::{Aes128EcbDec, Aes128EcbEnc};

    // NIST SP 800-38A F.1.1 — ECB-AES128.Encrypt
    #[test]
    fn aes128_ecb_enc_nist_f1_1() {
        common::init_wolfcrypt();
        let key = common::hex_decode(aes_38a::ecb_aes128_enc::KEY);
        let pt = common::hex_decode(aes_38a::ecb_aes128_enc::PT);
        let expected_ct = common::hex_decode(aes_38a::ecb_aes128_enc::CT);

        let mut cipher = Aes128EcbEnc::new_from_slice(&key).expect("key init failed");
        let mut out = vec![0u8; pt.len()];
        let buf = InOutBuf::new(&pt, &mut out).expect("length mismatch");
        let (blocks, tail) = buf.into_chunks();
        assert!(tail.is_empty(), "plaintext length must be block-aligned");
        cipher.encrypt_blocks_inout(blocks);
        assert_eq!(out, expected_ct, "ECB-AES128 encrypt mismatch");
    }

    // NIST SP 800-38A F.1.2 — ECB-AES128.Decrypt
    #[test]
    fn aes128_ecb_dec_nist_f1_2() {
        common::init_wolfcrypt();
        let key = common::hex_decode(aes_38a::ecb_aes128_enc::KEY);
        let ct = common::hex_decode(aes_38a::ecb_aes128_enc::CT);
        let expected_pt = common::hex_decode(aes_38a::ecb_aes128_enc::PT);

        let mut cipher = Aes128EcbDec::new_from_slice(&key).expect("key init failed");
        let mut out = vec![0u8; ct.len()];
        let buf = InOutBuf::new(&ct, &mut out).expect("length mismatch");
        let (blocks, tail) = buf.into_chunks();
        assert!(tail.is_empty(), "ciphertext length must be block-aligned");
        cipher.decrypt_blocks_inout(blocks);
        assert_eq!(out, expected_pt, "ECB-AES128 decrypt mismatch");
    }
}

// ---------------------------------------------------------------------------
// CBC — NIST SP 800-38A Appendix F.2
// ---------------------------------------------------------------------------

#[cfg(aes_cbc)]
mod cbc_tests {
    use super::{aes_38a, common};
    use cipher::{BlockModeDecrypt, BlockModeEncrypt, InOutBuf, KeyIvInit};
    use wolfssl_wolfcrypt::aes::{Aes128CbcDec, Aes128CbcEnc};

    // NIST SP 800-38A F.2.1 — CBC-AES128.Encrypt
    #[test]
    fn aes128_cbc_enc_nist_f2_1() {
        common::init_wolfcrypt();
        let key = common::hex_decode(aes_38a::cbc_aes128_enc::KEY);
        let iv = common::hex_decode(aes_38a::cbc_aes128_enc::IV);
        let pt = common::hex_decode(aes_38a::cbc_aes128_enc::PT);
        let expected_ct = common::hex_decode(aes_38a::cbc_aes128_enc::CT);

        let mut cipher =
            Aes128CbcEnc::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut out = vec![0u8; pt.len()];
        let buf = InOutBuf::new(&pt, &mut out).expect("length mismatch");
        let (blocks, tail) = buf.into_chunks();
        assert!(tail.is_empty(), "plaintext length must be block-aligned");
        cipher.encrypt_blocks_inout(blocks);
        assert_eq!(out, expected_ct, "CBC-AES128 encrypt mismatch");
    }

    // NIST SP 800-38A F.2.2 — CBC-AES128.Decrypt
    #[test]
    fn aes128_cbc_dec_nist_f2_2() {
        common::init_wolfcrypt();
        let key = common::hex_decode(aes_38a::cbc_aes128_enc::KEY);
        let iv = common::hex_decode(aes_38a::cbc_aes128_enc::IV);
        let ct = common::hex_decode(aes_38a::cbc_aes128_enc::CT);
        let expected_pt = common::hex_decode(aes_38a::cbc_aes128_enc::PT);

        let mut cipher =
            Aes128CbcDec::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut out = vec![0u8; ct.len()];
        let buf = InOutBuf::new(&ct, &mut out).expect("length mismatch");
        let (blocks, tail) = buf.into_chunks();
        assert!(tail.is_empty(), "ciphertext length must be block-aligned");
        cipher.decrypt_blocks_inout(blocks);
        assert_eq!(out, expected_pt, "CBC-AES128 decrypt mismatch");
    }
}

// ---------------------------------------------------------------------------
// CTR — NIST SP 800-38A Appendix F.5
// ---------------------------------------------------------------------------
//
// CTR-AES128.Encrypt F.5.1
//   Key: 2b7e151628aed2a6abf7158809cf4f3c
//   IV (initial counter block): f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
//   PT: 6bc1bee2...be66c3710  (64 bytes, 4 blocks)
//   CT: 874d6191...a0f3009cee (64 bytes)
//
// Vectors verified independently via pyca/cryptography AES-CTR.

#[cfg(aes_ctr)]
mod ctr_tests {
    use super::common;
    use cipher::{KeyIvInit, StreamCipher};
    use wolfssl_wolfcrypt::aes::Aes128Ctr;

    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const PT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    // CT verified via pyca/cryptography (AES-CTR, same key/IV/PT).
    const CT: &str = concat!(
        "874d6191b620e3261bef6864990db6ce",
        "9806f66b7970fdff8617187bb9fffdff",
        "5ae4df3edbd5d35e5b4f09020db03eab",
        "1e031dda2fbe03d1792170a0f3009cee",
    );

    // NIST SP 800-38A F.5.1 — CTR-AES128.Encrypt
    #[test]
    fn aes128_ctr_enc_nist_f5_1() {
        common::init_wolfcrypt();
        let key = common::hex_decode(KEY);
        let iv = common::hex_decode(IV);
        let pt = common::hex_decode(PT);
        let expected_ct = common::hex_decode(CT);

        let mut cipher =
            Aes128Ctr::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut buf = pt.clone();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected_ct, "CTR-AES128 encrypt mismatch");
    }

    // NIST SP 800-38A F.5.2 — CTR-AES128.Decrypt (CTR is symmetric: CT XOR keystream = PT)
    #[test]
    fn aes128_ctr_dec_nist_f5_2() {
        common::init_wolfcrypt();
        let key = common::hex_decode(KEY);
        let iv = common::hex_decode(IV);
        let ct = common::hex_decode(CT);
        let expected_pt = common::hex_decode(PT);

        let mut cipher =
            Aes128Ctr::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut buf = ct.clone();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected_pt, "CTR-AES128 decrypt mismatch");
    }
}

// ---------------------------------------------------------------------------
// OFB — NIST SP 800-38A Appendix F.4
// ---------------------------------------------------------------------------
//
// OFB-AES128.Encrypt F.4.1
//   Key: 2b7e151628aed2a6abf7158809cf4f3c
//   IV:  000102030405060708090a0b0c0d0e0f
//   PT:  6bc1bee2...be66c3710  (64 bytes, 4 blocks)
//   CT:  3b3fd92e...d6ae5e     (64 bytes)
//
// Note: the CT provided in the Agent R brief contained 129 hex chars (corrupted).
// The value below was computed with pyca/cryptography as the independent oracle
// and matches the NIST SP 800-38A F.4 table exactly.

#[cfg(aes_ofb)]
mod ofb_tests {
    use super::common;
    use cipher::{KeyIvInit, StreamCipher};
    use wolfssl_wolfcrypt::aes::Aes128Ofb;

    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    const PT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    // CT verified via pyca/cryptography (AES-OFB, same key/IV/PT).
    // The Agent R brief had a corrupted 129-char hex string; this is the correct value.
    const CT: &str = concat!(
        "3b3fd92eb72dad20333449f8e83cfb4a",
        "7789508d16918f03f53c52dac54ed825",
        "9740051e9c5fecf64344f7a82260edcc",
        "304c6528f659c77866a510d9c1d6ae5e",
    );

    // NIST SP 800-38A F.4.1 — OFB-AES128.Encrypt
    #[test]
    fn aes128_ofb_enc_nist_f4_1() {
        common::init_wolfcrypt();
        let key = common::hex_decode(KEY);
        let iv = common::hex_decode(IV);
        let pt = common::hex_decode(PT);
        let expected_ct = common::hex_decode(CT);

        let mut cipher =
            Aes128Ofb::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut buf = pt.clone();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected_ct, "OFB-AES128 encrypt mismatch");
    }

    // NIST SP 800-38A F.4.2 — OFB-AES128.Decrypt (OFB is symmetric: CT XOR keystream = PT)
    #[test]
    fn aes128_ofb_dec_nist_f4_2() {
        common::init_wolfcrypt();
        let key = common::hex_decode(KEY);
        let iv = common::hex_decode(IV);
        let ct = common::hex_decode(CT);
        let expected_pt = common::hex_decode(PT);

        let mut cipher =
            Aes128Ofb::new_from_slices(&key, &iv).expect("key/iv init failed");
        let mut buf = ct.clone();
        cipher.apply_keystream(&mut buf);
        assert_eq!(buf, expected_pt, "OFB-AES128 decrypt mismatch");
    }
}
