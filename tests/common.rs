#![allow(dead_code)]

use std::sync::Once;
use wolfssl_wolfcrypt::wolfcrypt_init;

static INIT: Once = Once::new();

pub fn init_wolfcrypt() {
    INIT.call_once(|| {
        wolfcrypt_init().expect("wolfCrypt init failed");
    });
}

/// Decode a hex string to bytes. Panics on invalid hex (test infrastructure).
pub fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("invalid hex in test vector: {e}"))
}

/// Load a Wycheproof JSON test file. Panics if file not found (run setup.sh first).
pub fn load_wycheproof_json(path: &str) -> serde_json::Value {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "Cannot open Wycheproof test vectors at {path}: {e}\n\
             Run './setup.sh' first to clone the test vector repositories."
        )
    });
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("invalid JSON in {path}: {e}"))
}
