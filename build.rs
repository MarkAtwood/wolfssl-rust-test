//! Test crate build script.
//!
//! Mirrors the cfg flags emitted by wolfssl-wolfcrypt/build.rs so that
//! #[cfg(aes_ecb)], #[cfg(aes_gcm)], etc. work in test files.
//!
//! Flags are emitted unconditionally (assumes wolfSSL built with --enable-all).
//! If a specific algorithm is absent, the test will fail to compile with a
//! "type not found" error from wolfssl_wolfcrypt — which documents the gap.
fn main() {
    let cfgs: &[&str] = &[
        "aes", "aes_ecb", "aes_cbc", "aes_ctr", "aes_ofb",
        "aes_gcm", "aes_ccm",
        "chacha20_poly1305", "xchacha20_poly1305",
        "sha", "sha256", "sha384", "sha512",
        "sha3", "shake128", "shake256",
        "hmac", "cmac",
        "ecc", "ecc_sign", "ecc_verify", "ecc_import", "ecc_export",
        "ed25519", "ed448", "rsa",
        "mlkem", "lms", "dilithium",
        "hkdf", "random",
    ];
    for cfg in cfgs {
        println!("cargo::rustc-cfg={cfg}");
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }
}
