//! NIST SP 800-38A Appendix F — AES Mode Sample Records (as hex strings).
//! Decode with hex::decode() at test time.
//! Source: NIST SP 800-38A, https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

/// F.1.1 ECB-AES128.Encrypt
pub mod ecb_aes128_enc {
    pub const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    /// 4 plaintext blocks (64 bytes)
    pub const PT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    /// 4 ciphertext blocks (64 bytes)
    pub const CT: &str = concat!(
        "3ad77bb40d7a3660a89ecaf32466ef97",
        "f5d3d58503b9699de785895a96fdbaaf",
        "43b1cd7f598ece23881b00e3ed030688",
        "7b0c785e27e8ad3f8223207104725dd4",
    );
}

/// F.2.1 CBC-AES128.Encrypt
pub mod cbc_aes128_enc {
    pub const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    pub const IV: &str = "000102030405060708090a0b0c0d0e0f";
    /// 4 plaintext blocks (64 bytes) — same as ECB input
    pub const PT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    pub const CT: &str = concat!(
        "7649abac8119b246cee98e9b12e9197d",
        "5086cb9b507219ee95db113a917678b2",
        "73bed6b8e3c1743b7116e69e22229516",
        "3ff1caa1681fac09120eca307586e1a7",
    );
}
