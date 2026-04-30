//! NIST SP 800-38B Appendix D — AES-CMAC Example Vectors (as hex strings).
//! Decode with hex::decode() at test time.
//! Source: NIST SP 800-38B, https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf
//!
//! Each submodule: KEY = AES key, MSG = message bytes (empty string = zero-length),
//! TAG = expected 16-byte CMAC output.

/// D.1 Example vectors with AES-128 (16-byte key)
pub mod aes128 {
    pub const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";

    /// D.1 Example 1: Mlen = 0
    pub mod ex1 {
        pub const MSG: &str = "";
        pub const TAG: &str = "bb1d6929e95937287fa37d129b756746";
    }

    /// D.1 Example 2: Mlen = 16
    pub mod ex2 {
        pub const MSG: &str = "6bc1bee22e409f96e93d7e117393172a";
        pub const TAG: &str = "070a16b46b4d4144f79bdd9dd04a287c";
    }

    /// D.1 Example 3: Mlen = 40
    pub mod ex3 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411",
        );
        pub const TAG: &str = "dfa66747de9ae63030ca32611497c827";
    }

    /// D.1 Example 4: Mlen = 64
    pub mod ex4 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        );
        pub const TAG: &str = "51f0bebf7e3b9d92fc49741779363cfe";
    }
}

/// D.2 Example vectors with AES-192 (24-byte key)
pub mod aes192 {
    pub const KEY: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";

    /// D.2 Example 1: Mlen = 0
    pub mod ex1 {
        pub const MSG: &str = "";
        pub const TAG: &str = "d17ddf46adaacde531cac483de7a9367";
    }

    /// D.2 Example 2: Mlen = 16
    pub mod ex2 {
        pub const MSG: &str = "6bc1bee22e409f96e93d7e117393172a";
        pub const TAG: &str = "9e99a7bf31e710900662f65e617c5184";
    }

    /// D.2 Example 3: Mlen = 40
    pub mod ex3 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411",
        );
        pub const TAG: &str = "3d75c194ed96070444a9fa7ec740ecf8";
    }

    /// D.2 Example 4: Mlen = 64
    pub mod ex4 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        );
        pub const TAG: &str = "a1d5df0eed790f794d77589659f39a11";
    }
}

/// D.3 Example vectors with AES-256 (32-byte key)
pub mod aes256 {
    pub const KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

    /// D.3 Example 1: Mlen = 0
    pub mod ex1 {
        pub const MSG: &str = "";
        pub const TAG: &str = "028962f61b7bf89efc6b551f4667d983";
    }

    /// D.3 Example 2: Mlen = 16
    pub mod ex2 {
        pub const MSG: &str = "6bc1bee22e409f96e93d7e117393172a";
        pub const TAG: &str = "28a7023f452e8f82bd4bf28d8c37c35c";
    }

    /// D.3 Example 3: Mlen = 40
    pub mod ex3 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411",
        );
        pub const TAG: &str = "156727dc0878944a023c1fe03bad6d93";
    }

    /// D.3 Example 4: Mlen = 64
    pub mod ex4 {
        pub const MSG: &str = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        );
        pub const TAG: &str = "e1992190549f6ed5696a2c056c315410";
    }
}
