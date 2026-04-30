//! Inline SHA known-answer vectors from NIST FIPS 180-4 and FIPS 202.
//! Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
//!
//! `input` is the ASCII message (use as bytes via .as_bytes()).
//! `output` is the expected digest as a lowercase hex string.

pub struct TestVector {
    pub input: &'static str,
    pub output: &'static str,
}

/// FIPS 180-4 SHA-256 known-answer vectors.
pub const SHA256: &[TestVector] = &[
    // Empty string
    TestVector {
        input: "",
        output: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    // "abc"
    TestVector {
        input: "abc",
        output: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
];

/// FIPS 180-4 SHA-512 known-answer vectors.
pub const SHA512: &[TestVector] = &[
    // Empty string
    TestVector {
        input: "",
        output: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
];

/// FIPS 202 SHA3-256 known-answer vectors.
pub const SHA3_256: &[TestVector] = &[
    // Empty string
    TestVector {
        input: "",
        output: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    },
];
