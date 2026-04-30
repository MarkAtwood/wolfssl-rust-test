# wolfssl-wolfcrypt Rust Trait Correctness Test Suite — Plan

## Purpose

The upstream C library is already tested by **wolfSSL/wychcheck**, which runs
Wycheproof, NIST ACVP, and RFC vectors against wolfCrypt's C APIs (triggered
by the `wycheproof.yml` GitHub Action, PR #10258).

This suite tests the **Rust trait adapter layer** — the `impl digest::Digest`,
`impl cipher::StreamCipher`, `impl aead::AeadInPlace`, `impl signature::Signer`,
etc. that live in `wolfssl-wolfcrypt`.  If a trait impl uses the wrong key
size, nonce size, tag size, output size, or calls the wrong underlying C
function, wychcheck will not catch it because wychcheck does not use the Rust
traits.

The suite also records the gaps and API issues found in the PR review:

- **PR #10248** (merged Apr 17) — digest + signature traits
- **PR #10305** (open Apr 24) — mac, kem, password-hash traits + bug fixes

---

## What counts as a valid test oracle

Per project test integrity rules, every assertion must be grounded in an
independent source:

| Source | Location after setup.sh | Used for |
|---|---|---|
| NIST FIPS 180-4 / 202 examples | inline `hex!()` in `testvectors/nist/sha_inline.rs` | digest::Digest |
| NIST SP 800-38B Appendix D | inline `hex!()` in `testvectors/nist/cmac_38b.rs` | CMAC (all key sizes) |
| NIST SP 800-38A Appendix F | inline `hex!()` in `testvectors/nist/aes_38a.rs` | AES ECB/CBC/CTR/OFB |
| NIST FIPS 203 ACVP | `external/wychcheck/testvectors_acvp/ML-KEM-*/` | ML-KEM kem trait |
| RFC 8032 (EdDSA) | `external/wychcheck/testvectors_rfc/rfc8032_eddsa_test.json` | Ed25519, Ed448 |
| Wycheproof `hmac_sha*_test.json` | `external/wycheproof/testvectors_v1/` | HMAC all variants |
| Wycheproof `pbkdf2_hmac*_test.json` | `external/wycheproof/testvectors_v1/` | PBKDF2 all variants |
| Wycheproof `aes_gcm_test.json` etc. | `external/wycheproof/testvectors_v1/` | AEAD |
| Wycheproof `ecdsa_secp*_test.json` | `external/wycheproof/testvectors_v1/` | ECDSA P-256/384/521 |
| Wycheproof `rsa_signature_*_test.json` | `external/wycheproof/testvectors_v1/` | RSA PKCS#1v1.5 verify |

Round-trip tests (encrypt-then-decrypt with the same code) prove only that the
code runs; they are **not** acceptable as the sole oracle.

---

## Repository layout

```
wolfssl-rust-test/
  PLAN.md                  <- this file
  setup.sh                 <- shallow-clones external repos (see below)
  Cargo.toml               <- path dep on ../wolfssl/wrapper/rust/wolfssl-wolfcrypt
  build.rs                 <- locate wolfSSL library (mirrors upstream build.rs approach)
  testvectors/
    nist/
      aes_38a.rs           <- NIST SP 800-38A Appendix F vectors, embedded as hex!() literals
      cmac_38b.rs          <- NIST SP 800-38B Appendix D vectors, embedded as hex!() literals
      sha_inline.rs        <- handful of NIST FIPS 180-4/202 KAT examples, embedded inline
  external/                <- populated by setup.sh; git-ignored
    wychcheck/             <- shallow clone of wolfSSL/wychcheck
      testvectors_acvp/    <- NIST ACVP ML-KEM/ML-DSA vectors (bundled in repo)
      testvectors_rfc/     <- RFC 8032 EdDSA, RFC 5869 HKDF, RFC 8439 ChaCha20 (bundled)
    wycheproof/            <- shallow clone of google/wycheproof
      testvectors_v1/      <- all Wycheproof JSON test files
  tests/
    common.rs              <- wolfcrypt_init/cleanup, hex decode helper, JSON loader
    test_digest.rs         <- SHA / SHA3 / SHAKE via digest::Digest
    test_cipher.rs         <- AES ECB/CBC/CTR/OFB via cipher::* traits
    test_aead.rs           <- AES-GCM, AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305
    test_mac.rs            <- HMAC and CMAC via digest::Mac (PR #10305)
    test_signature.rs      <- ECDSA P-256/384/521, Ed25519, Ed448, RSA PKCS1v15
    test_kem.rs            <- ML-KEM-512/768/1024 via kem::Kem (PR #10305)
    test_pbkdf2.rs         <- PBKDF2 via password-hash traits (PR #10305)
    test_rand_core.rs      <- RNG via rand_core::TryCryptoRng
    test_api_gaps.rs       <- compile-time and runtime API issue documentation
```

---

## Cargo.toml sketch

```toml
[package]
name = "wolfssl-rust-test"
version = "0.1.0"
edition = "2021"

[dependencies]
wolfssl-wolfcrypt = { path = "../wolfssl/wrapper/rust/wolfssl-wolfcrypt",
  features = ["rand_core", "aead", "cipher", "digest", "signature",
               "mac", "kem", "password-hash"] }
hex = "0.4"
serde_json = "1"   # for loading Wycheproof JSON

[dev-dependencies]
aead = { version = "0.5", features = ["dev"] }
digest = { version = "0.11", features = ["dev", "mac"] }
cipher = "0.5"
```

The `path` dep means the suite runs against whatever is currently checked out
in `~/WORK/wolfssl`.  To test the PR #10305 branch, check it out there first.

---

## Per-module test plan

### 1. `test_digest.rs` — `digest::Digest` (PR #10248)

**What it proves:** The `sha_digest.rs` trait impls call the right wolfCrypt
hash function and produce the correct byte output.

**Oracle:** NIST SHA byte-oriented test vectors (CAVS `.rsp` files, parsed
from `testvectors/nist/sha/`).  These are the same vectors NIST uses for
FIPS 140 validation.

**Test cases per algorithm:**

| Type | Algorithm | Vec count |
|---|---|---|
| `SHA` | SHA-1 | short + long message from ShortMsg.rsp |
| `SHA224` | SHA-224 | same |
| `SHA256` | SHA-256 | same |
| `SHA384` | SHA-384 | same |
| `SHA512` | SHA-512 | same |
| `SHA3_224`–`SHA3_512` | SHA3 family | NIST SHA3 CAVS |
| `SHAKE128`, `SHAKE256` | XOF | NIST SHAKE variable-output vectors |

**What to assert:**

```rust
// For each (input, expected_output) vector:
let mut hasher = SHA256::new();       // digest::Digest
hasher.update(input);
let result = hasher.finalize();
assert_eq!(result.as_slice(), expected_output);
```

For SHAKE (XOF), use `digest::ExtendableOutput::finalize_xof` and read
`output_len` bytes, comparing to the NIST expected output.

**Gap exposed:** The current local tree has no `sha_digest.rs` — these tests
will fail to compile until PR #10248's changes are present.

---

### 2. `test_cipher.rs` — `cipher::*` traits

**What it proves:** The type parameters (`KeySize`, `IvSize`, `BlockSize`) are
correct and the encrypt/decrypt output matches known plaintext/ciphertext pairs.

**Oracle:** NIST SP 800-38A, Appendix F — "Sample Records."  Covers ECB, CBC,
CTR for AES-128/192/256.  OFB vectors from the same document.

**Test cases:**

| Mode | Key sizes | Direction | Vector source |
|---|---|---|---|
| ECB | 128, 192, 256 | Enc + Dec | NIST 800-38A F.1, F.2 |
| CBC | 128, 192, 256 | Enc + Dec | NIST 800-38A F.2 |
| CTR | 128, 192, 256 | Enc (= Dec) | NIST 800-38A F.5 |
| OFB | 128, 192, 256 | Enc (= Dec) | NIST 800-38A F.4 |

**What to assert (example for ECB):**

```rust
use cipher::{BlockEncrypt, KeyInit};
let cipher = Aes128EcbEnc::new_from_slice(key).unwrap();
let mut block = GenericArray::clone_from_slice(plaintext);
cipher.encrypt_block(&mut block);
assert_eq!(block.as_slice(), expected_ciphertext);
```

**Gap exposed:** AES-OFB types in the current crate only implement
`cipher::KeySizeUser` — `IvSizeUser`, `KeyIvInit`, and `StreamCipher` are
implemented but were not visible in the Grep output (behind `#[cfg(aes_ofb)]`).
These tests will confirm whether they are actually wired end-to-end.

---

### 3. `test_aead.rs` — `aead::AeadInPlace`

**What it proves:** The AEAD wrappers (GCM, CCM, ChaCha20-Poly1305,
XChaCha20-Poly1305) correctly seal and open, and reject tampered ciphertexts.

**Oracle:** Wycheproof JSON from the shallow-cloned `external/wycheproof/`:
- `external/wycheproof/testvectors_v1/aes_gcm_test.json`
- `external/wycheproof/testvectors_v1/aes_ccm_test.json`
- `external/wycheproof/testvectors_v1/chacha20_poly1305_test.json`
- `external/wycheproof/testvectors_v1/xchacha20_poly1305_test.json`

Parse the JSON at test time with `serde_json`.  For each test group, filter
by key size (128 or 256 bit), nonce size (12 bytes for GCM/ChaCha), and tag
size (16 bytes).  Run both `result == "valid"` (expect Ok) and
`result == "invalid"` (expect Err) cases.

```rust
// Wycheproof "valid" case:
let cipher = Aes128Gcm::new_from_slice(key).unwrap();
let mut buf = plaintext.to_vec();
let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buf).unwrap();
assert_eq!(buf, expected_ciphertext);
assert_eq!(tag.as_slice(), expected_tag);

// Wycheproof "invalid" case:
let mut buf = ciphertext.to_vec();
assert!(cipher.decrypt_in_place_detached(nonce, aad, &mut buf, tag).is_err());
```

**Gap exposed:** Missing `Aes192Gcm` and `Aes192Ccm` — the crate skips the
192-bit key size.  These tests confirm the gap; a `#[ignore]` marker documents it.

---

### 4. `test_mac.rs` — `digest::Mac` (PR #10305)

**What it proves:** HMAC and CMAC trait impls compute correct MACs and reject
wrong tags.

**Oracles:**

- **CMAC AES-128:** NIST SP 800-38B Appendix D.1, all 4 examples
  (Mlen = 0, 16, 40, 64 bytes) — embedded inline from `testvectors/nist/cmac_38b.rs`.
  The PR tests only Example 2.
- **CMAC AES-192:** NIST SP 800-38B Appendix D.2, all 4 examples — embedded inline.
  *Not tested in PR at all.*
- **CMAC AES-256:** NIST SP 800-38B Appendix D.3, all 4 examples — embedded inline.
  *Not tested in PR at all.*
- **HMAC-SHA-1:** `external/wycheproof/testvectors_v1/hmac_sha1_test.json`
  (superset of RFC 2202).  *Not tested in PR.*
- **HMAC-SHA-224:** `external/wycheproof/testvectors_v1/hmac_sha224_test.json`.
  *Not tested in PR.*
- **HMAC-SHA-256:** `external/wycheproof/testvectors_v1/hmac_sha256_test.json`
  (superset of RFC 4231).  PR tests 3 hand-picked cases from this set.
- **HMAC-SHA-384:** `external/wycheproof/testvectors_v1/hmac_sha384_test.json`.
  *Not tested in PR.*
- **HMAC-SHA-512:** `external/wycheproof/testvectors_v1/hmac_sha512_test.json`.
  *Not tested in PR.*
- **HMAC-SHA-512/224, SHA-512/256:** `external/wycheproof/testvectors_v1/hmac_sha512_224_test.json`,
  `hmac_sha512_256_test.json`.  *Not tested in PR.*
- **HMAC-SHA3-224/256/384/512:** `external/wycheproof/testvectors_v1/hmac_sha3_*_test.json`.
  *Not tested in PR.*

Additionally, run `verify_slice` on a wrong tag and assert `Err` for each
algorithm.

**Gap exposed:**

1. PR #10305 CMAC tests cover only AES-128, only 1 of 4 NIST vector lengths.
2. PR #10305 HMAC tests cover only SHA-256, only 3 of 7 RFC 4231 vectors.
3. No AES-192 or AES-256 CMAC coverage in the PR.

---

### 5. `test_signature.rs` — `signature::{Signer, Verifier}` (PR #10248)

**What it proves:** The ECDSA, EdDSA, and RSA PKCS#1v1.5 signature wrappers
produce valid signatures that can be verified, and reject invalid ones.

**Oracles:**

| Algorithm | Source |
|---|---|
| ECDSA P-256 | `external/wycheproof/testvectors_v1/ecdsa_secp256r1_sha256_test.json` |
| ECDSA P-384 | `external/wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json` |
| ECDSA P-521 | `external/wycheproof/testvectors_v1/ecdsa_secp521r1_sha512_p1363_test.json` |
| Ed25519, Ed448 | `external/wychcheck/testvectors_rfc/rfc8032_eddsa_test.json` (bundled in wychcheck) |
| RSA PKCS#1v1.5 verify | `external/wycheproof/testvectors_v1/rsa_signature_2048_sha256_test.json` |

For signing, use a fixed test key to produce a deterministic signature (or use
the signer and then verify with the verifier — acceptable here because signing
and verifying use different code paths and the verifier is checked against
external vectors independently).

**Gap exposed:** The local tree has no `ecdsa.rs` or `rsa_pkcs1v15.rs` —
compile failure until PR #10248 changes are present.

---

### 6. `test_kem.rs` — `kem::Kem` (PR #10305)

**What it proves:** The ML-KEM kem trait wrappers compute correct
encapsulation/decapsulation.

**Oracle:** NIST FIPS 203 ACVP vectors bundled in wychcheck:
- `external/wychcheck/testvectors_acvp/ML-KEM-encapDecap-FIPS203/`
- `external/wychcheck/testvectors_acvp/ML-KEM-keyGen-FIPS203/`

These are deterministic byte-exact vectors.  Feed the ACVP `ek` (encapsulation
key bytes) and `m` (encapsulation randomness) and compare the resulting `k`
(shared secret) and `c` (ciphertext) byte-for-byte.

**Gap exposed:** The PR #10305 tests are round-trip only — no NIST KAT vectors.
These tests directly demonstrate that gap and fill it.

Note: the ML-KEM kem trait's `encapsulate` takes an RNG, but NIST KAT testing
requires deterministic encapsulation from a fixed seed.  The implementation
plan must decide whether to expose a `encapsulate_with_seed()` function or
access the deterministic wolfCrypt API `wc_MlKemKey_Encapsulate` directly with
a seeded deterministic RNG.  **This is a design question that must be resolved
before implementation.**

---

### 7. `test_pbkdf2.rs` — `password-hash` traits (PR #10305)

**What it proves:** The PBKDF2 password-hash impl computes correct output.

**Oracle:** Wycheproof PBKDF2 JSON from the shallow-cloned `external/wycheproof/`:
- `external/wycheproof/testvectors_v1/pbkdf2_hmacsha1_test.json` (superset of RFC 6070)
- `external/wycheproof/testvectors_v1/pbkdf2_hmacsha256_test.json`
- `external/wycheproof/testvectors_v1/pbkdf2_hmacsha384_test.json`
- `external/wycheproof/testvectors_v1/pbkdf2_hmacsha512_test.json`

All four files use the same JSON schema so a single parser handles them all.
The SHA-1 file is a strict superset of RFC 6070 §2 cases.

**Gap exposed:** All current PR #10305 tests are round-trip.  `test_deterministic_output`
(hash twice, compare) proves only determinism, not correctness.  These tests
directly demonstrate the gap.

---

### 8. `test_rand_core.rs` — `rand_core::TryCryptoRng`

**What it proves:** The `RNG` type correctly implements the trait and produces
non-zero output for normal invocations.

**No external oracle is appropriate for RNG output** — DRBG self-tests are
internal to wolfCrypt and run at init.  Tests here verify:

1. `RNG` implements `rand_core::TryCryptoRng` (compile-time proof).
2. `try_fill_bytes` returns `Ok(())` and fills the buffer (not all-zeros).
3. Two successive calls produce different output.
4. `PrimInt` bound on `generate_block` (PR #10305 change) is exercised
   with `u8`, `u16`, `u32`, `u64` element types.

---

### 9. `test_api_gaps.rs` — documented API issues

This file is a registry of issues found in the PR review that cannot be
expressed as correctness tests but should be on record.  Each is a commented
`#[test]` that either:
- demonstrates a compile error via `compile_fail` doc-test, or
- demonstrates a runtime API shape mismatch.

**Issues to document:**

1. **`lms::Lms::sigs_left()` renamed to `has_sigs_left()`** (PR #10305, `lms.rs`).
   Breaking rename, no deprecation shim, no version bump in `Cargo.toml`.
   Document with a `compile_fail` test calling `sigs_left()`.

2. **`mlkem::MlKem::encode_public_key` return type** changed from
   `Result<usize, i32>` to `Result<(), i32>` (PR #10305, `mlkem.rs`).
   Breaking change.  Document with a `compile_fail` test.

3. **Missing `Aes192Gcm` and `Aes192Ccm`**.  Document with a
   `compile_fail` test attempting to use these types.

4. **CMAC/HMAC Mac types are not `Clone` or `Reset`**.  Document with a
   `compile_fail` test attempting `mac.clone()`.

5. **`ecc::ECC::verify` result fix** (`res != 0` → `res == 1`, PR #10305).
   Add a test using a known-valid and a known-invalid ECDSA signature
   to confirm the verifier returns `Ok(true)` / `Ok(false)` correctly,
   not a spurious true from a non-1 positive rc.

---

## Test vector acquisition

All external vectors arrive via two shallow clones.  The `setup.sh` script
handles this; it is idempotent (skips clones that already exist).

```sh
#!/usr/bin/env bash
set -euo pipefail

# wolfSSL/wychcheck — bundles NIST ACVP ML-KEM/ML-DSA vectors and RFC vectors
if [ ! -d external/wychcheck ]; then
  git clone --depth 1 https://github.com/wolfSSL/wychcheck external/wychcheck
fi

# google/wycheproof — Wycheproof JSON test vectors (AEAD, HMAC, PBKDF2,
# ECDSA, EdDSA, RSA, …)
# wychcheck lists this as a submodule but we clone it directly — same content,
# no recursive submodule machinery needed.
if [ ! -d external/wycheproof ]; then
  git clone --depth 1 https://github.com/google/wycheproof external/wycheproof
fi

# wychcheck also lists usnistgov/ACVP-Server and google/boringssl as submodules
# but marks them update=none (reference-only, 900 MB+).  Do NOT clone them.
```

After running `setup.sh`, the directory tree is:

```
external/
  wychcheck/
    testvectors_acvp/    <- NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA ACVP vectors
    testvectors_rfc/     <- rfc8032_eddsa_test.json, rfc5869_hkdf_test.json, …
  wycheproof/
    testvectors_v1/      <- all Wycheproof JSON (AEAD, HMAC, PBKDF2, ECDSA, RSA, …)
```

### NIST AES / CMAC vectors (inline)

The SP 800-38A (AES modes) and SP 800-38B (CMAC) sample records are short
enough to embed directly as `hex!()` literals in `testvectors/nist/`:

- **SP 800-38A Appendix F**: 3 key sizes × 4 modes (ECB, CBC, CTR, OFB) ×
  2 directions = ~24 vector sets.  Each set is 4 plaintext/ciphertext block
  pairs.  Total embedded data is a few hundred bytes.
- **SP 800-38B Appendix D**: 3 key sizes × 4 message lengths = 12 vectors.
  Total embedded data is ~600 bytes.

Reference the standard and appendix letter in a comment beside each literal.
No network access required at test time.

### NIST SHA vectors (inline subset)

The SHA algorithms are tested with a small inline set drawn from the NIST
FIPS 180-4 and FIPS 202 example appendices (1–2 known-answer pairs per
algorithm).  These cover the "did we call the right hash function" question.
The wycheproof ECDSA/HMAC/signature files provide additional SHA coverage
implicitly as part of those scheme tests.

---

## Build configuration

The test suite must link against a compiled wolfSSL.  The build requires the
same wolfSSL configure flags used in the upstream CI:

```sh
# Minimum for all tests
./configure --enable-all --enable-dilithium

# For ML-KEM ACVP deterministic tests, wolfSSL must expose wc_MlKemKey_Encapsulate
# with a caller-supplied seed — verify this is possible before implementing test_kem.rs
```

Set `WOLFSSL_DIR` to the wolfSSL source tree before running:

```sh
WOLFSSL_DIR=~/WORK/wolfssl cargo test --features rand_core,aead,cipher,digest,signature,mac,kem,password-hash
```

---

## Relationship to wychcheck

| wychcheck tests | this suite tests |
|---|---|
| wolfCrypt C API produces correct bytes | Rust trait wrapper calls correct C API |
| wolfCrypt handles Wycheproof edge cases | Rust type parameters (KeySize, NonceSize, TagSize) are correct |
| C-level FIPS validation | Rust-level trait ergonomics (compile-time type safety) |

The two suites are complementary.  A bug in the Rust wrapper that uses the
wrong C function or passes arguments in the wrong order would pass wychcheck
and fail this suite.  A bug in wolfCrypt itself would fail wychcheck and
likely also fail this suite.

---

## Implementation order

1. `common.rs` + `test_digest.rs` (unblocked — NIST vectors, no PR dependency)
2. `test_cipher.rs` (unblocked — NIST SP 800-38A, no PR dependency)
3. `test_aead.rs` (unblocked — Wycheproof JSON, no PR dependency)
4. `test_signature.rs` (requires PR #10248 merge into local tree)
5. `test_mac.rs` (requires PR #10305 merge)
6. `test_pbkdf2.rs` (requires PR #10305 merge)
7. `test_kem.rs` (requires PR #10305 merge + resolution of deterministic-RNG design question)
8. `test_rand_core.rs` (unblocked)
9. `test_api_gaps.rs` (requires both PRs for complete coverage)
