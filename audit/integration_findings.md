# Integration Findings (from INTEGRATION agent)

## Library discovery order
1. $WOLFSSL_PREFIX/include + $WOLFSSL_PREFIX/lib (if env var set)
2. In-tree: from wolfssl-wolfcrypt location goes ../../.. (= ~/WORK/wolfssl)
3. System fallback

## Current ~/WORK/wolfssl build
- Static library: ~/WORK/wolfssl/src/.libs/libwolfssl.a (4.1 MB, Apr 21)
- Configure flags: --enable-crypto2dev --enable-cryptocb --enable-debug --disable-shared CFLAGS="-g -O0"
- MISSING: most crypto algorithms (no --enable-sha, --enable-aes, --enable-ecc, etc.)
- ACTION NEEDED: rebuild wolfssl with --enable-all --enable-dilithium before running tests

## cfg flag propagation
- wolfssl-wolfcrypt's build.rs scans bindgen output for C function symbols
- Emits cargo:rustc-cfg=<flag> for each present symbol
- Flags propagate to ALL crates in the build graph, including test crate
- Test functions should gate on same cfg flags: #[cfg(sha256)] fn test_sha256_digest() {}

## Test crate needs
- NO separate build.rs needed — dependency's build.rs handles linking
- Must set WOLFSSL_PREFIX or rely on in-tree detection
- In-tree path from test crate (at ~/WORK/wolfssl-rust-test): ../wolfssl/src/.libs/libwolfssl.a
  BUT build.rs resolves path from wolfssl-wolfcrypt dir, not test crate dir
  So in-tree detection still works: wolfssl-wolfcrypt is at ../wolfssl/wrapper/rust/wolfssl-wolfcrypt/
  build.rs goes ../../.. from there → ~/WORK/wolfssl ✓

## Minimum wolfssl configure for all tests
```sh
./configure \
  --enable-all \
  --enable-dilithium \
  --disable-examples \
  --disable-shared
make -j$(nproc)
```

## Cipher crate version
- wolfssl-wolfcrypt Cargo.toml depends on cipher = "0.5"
- Only cipher 0.4.4 is in local ~/.cargo/registry (cached)
- Cargo will download 0.5 at first build — no blocker, just note

## Critical action item
MUST rebuild wolfssl at ~/WORK/wolfssl with --enable-all before any `cargo test`
