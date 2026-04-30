# Security Findings (from SECURITY agent) — prioritized

## Must-implement (into jpl.1 Infrastructure bead):
1. setup.sh: pin wychcheck + wycheproof to specific commit hashes after clone
2. tests/common.rs: assert_external_vectors_available() — panic if files missing before any test
3. All test modules: #![forbid(unsafe_code)] at top of each file
4. build.rs: require WOLFSSL_DIR env var, fail clearly if not set OR document that in-tree path suffices

## Must-implement (into each test module bead):
5. Use assert_bytes_eq(name, actual, expected) helper from common.rs instead of assert_eq!()
   — avoids printing full key/ciphertext on failure
6. Both valid AND invalid Wycheproof cases required (AEAD, HMAC, ECDSA)

## Nice-to-have (can be a separate small bead or added to jpl.1):
7. tests/common.rs: check wolfSSL version string at startup
8. CI: cargo audit --deny warnings

## Already in PLAN (no action needed):
- Wycheproof vectors as oracle for PBKDF2 (not round-trip)
- Round-trip limitation documented for RNG

## ML-KEM deterministic test (Threat 7):
- SECURITY recommends: use direct C API (wc_MlKemKey_Encapsulate with seeded state)
  rather than exposing test-only variant in kem trait
- This is the design question for jpl.7 — document in bead
