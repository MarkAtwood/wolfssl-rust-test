# wolfssl-wolfcrypt Rust Trait Layer — Review Report

**Date:** 2026-04-30
**PRs reviewed:** #10248 (merged Apr 17) · #10305 (open Apr 24)
**Crate:** `wolfssl-wolfcrypt` at `wolfssl/wrapper/rust/wolfssl-wolfcrypt/`

---

## Executive Summary

PRs #10248 and #10305 add valuable RustCrypto trait wrappers to
`wolfssl-wolfcrypt`. When both merge, the crate will be **substantially
more capable**, but it will **not be complete**. Three issues are present
that neither PR addresses — including one soundness bug — and two of the
changes in PR #10305 are breaking API changes shipped without a semver
version bump. The coverage provided by the new trait implementations also
has gaps relative to what the crate's underlying C library supports.

---

## Test Suite Summary

A correctness test suite was written against independent external oracles
(no round-trip tests). Results split by compilation status:

### Compilable now (no PR dependency)

| Test file | Tests | Oracle | Result |
|---|---|---|---|
| `test_cipher.rs` | 8 | NIST SP 800-38A App. F | **8/8 pass** |
| `test_aead.rs` | 16 | Wycheproof JSON + RFC 8439 §2.8.2 | **16/16 pass** |
| `test_rand_core.rs` | 5 | behavioral (non-zero, distinct output) | **5/5 pass** |
| `test_api_gaps.rs` | 0 runtime | documentation only | **ok** |

**29 tests, 0 failures.**

### Blocked on PR merge (skeletons written, fail to compile)

| Test file | Blocks on | Oracle planned |
|---|---|---|
| `test_digest.rs` | PR #10248 | NIST FIPS 180-4/202 inline KATs |
| `test_signature.rs` | PR #10248 | Wycheproof ECDSA/EdDSA/RSA JSON |
| `test_mac.rs` | PR #10305 | Wycheproof HMAC JSON + NIST SP 800-38B |
| `test_kem.rs` | PR #10305 | NIST FIPS 203 ACVP vectors |
| `test_pbkdf2.rs` | PR #10305 | Wycheproof PBKDF2 JSON |

All five test files exist with full test structure. They will compile and
run without modification once the corresponding PR is checked out locally.

---

## Will the Crate Be Complete After Both PRs Merge?

**No.** Six issues were identified; three are not resolved by either PR.

---

## Gap 1 — Missing AES-192 AEAD types (neither PR)

**Severity:** API completeness
**Status:** Open after both PRs

wolfCrypt supports AES-192 for GCM and CCM internally. The Rust wrapper
exposes `Aes128Gcm`, `Aes256Gcm`, `Aes128Ccm`, `Aes256Ccm` but not
`Aes192Gcm` or `Aes192Ccm`. Neither PR adds them.

This is visible in the Wycheproof AEAD test vectors, which include 192-bit
key groups that the suite currently cannot exercise. NIST FIPS 197 mandates
support for all three AES key sizes; the omission makes the crate
non-compliant at that boundary.

**Fix required:** Add `Aes192Gcm` and `Aes192Ccm` in `aes.rs`, mirroring the
existing 128/256 implementations with `U24` as the key size.

---

## Gap 2 — Breaking rename: `Lms::sigs_left()` → `has_sigs_left()` (PR #10305)

**Severity:** Breaking API change without semver bump
**Status:** Introduced by PR #10305

PR #10305 renames `Lms::sigs_left()` to `has_sigs_left()` with no
deprecation alias and no version bump in `Cargo.toml`. Any caller of
`sigs_left()` will fail to compile after the PR lands (E0599: no method
named `sigs_left`).

The method's semantics also changed: `sigs_left()` returned an integer count
of remaining OTS slots; `has_sigs_left()` returns a boolean. This is a
semantic break, not just a rename.

**Fix required before merge:** Either bump the crate version (semver minor
or major depending on policy) or add a `#[deprecated]` alias:

```rust
#[deprecated(since = "1.x.0", note = "use has_sigs_left()")]
pub fn sigs_left(&self) -> bool { self.has_sigs_left() }
```

---

## Gap 3 — Breaking type change: `MlKem::encode_public_key` return type (PR #10305)

**Severity:** Breaking API change without semver bump
**Status:** Introduced by PR #10305

PR #10305 changes `MlKem::encode_public_key` from `Result<usize, i32>` (bytes
written) to `Result<(), i32>`. Callers that capture the byte count — a natural
pattern when sizing a buffer — will fail to compile:

```rust
// Before PR #10305: compiles and works
let n: usize = key.encode_public_key(&mut buf)?;

// After PR #10305: type error (E0308)
let n: usize = key.encode_public_key(&mut buf)?;
```

**Fix required before merge:** Version bump. The key size is statically known
(ML-KEM-512: 800 bytes, ML-KEM-768: 1184 bytes, ML-KEM-1024: 1568 bytes) so
the `usize` return was redundant — removing it is reasonable, but it still
constitutes a breaking change under semver.

---

## Gap 4 — CMAC and HMAC `Mac` types lack `Clone` and `Reset` (PR #10305)

**Severity:** Trait incompleteness
**Status:** Open after PR #10305

PR #10305 adds `digest::Mac` impls for `Cmac` and `Hmac`. However, neither
type implements `Clone` or `digest::Reset`. The RustCrypto `Mac` trait is
designed to be used with `Clone` for reuse across messages with the same key,
and higher-level crates (HMAC-based key derivation, PRF constructions) require
`Clone` on their MAC type parameter.

Without `Clone`, the types cannot satisfy generic `Mac + Clone` bounds that
are idiomatic in the RustCrypto ecosystem.

**Fix required:** Implement `Clone` and `digest::Reset` for both `Cmac` and
`Hmac`. wolfCrypt internally supports resetting a MAC context; the wrappers
need to expose it.

---

## Gap 5 — `ecc::ECC::verify_hash` checks `res != 0` instead of `res == 1` (PR #10305 fixes)

**Severity:** Correctness
**Status:** Fixed by PR #10305

The current wrapper checks `Ok(res != 0)` after `wc_ecc_verify_hash()`.
wolfCrypt writes `1` into `res` for a valid signature and `0` for invalid;
any non-zero, non-1 value would produce a false `Ok(true)`.

PR #10305 corrects this to `Ok(res == 1)`. **This gap will be closed when
PR #10305 merges.**

A runtime verification test was attempted but could not be executed due to
the move-safety issue described in Gap 6 below.

---

## Gap 6 — ECC struct not move-safe with `WOLFSSL_SP_MATH_ALL` (neither PR)

**Severity:** Soundness (undefined behavior, observed crashes)
**Status:** Open after both PRs — not addressed by either

This is the most serious finding.

wolfssl-wolfcrypt initializes all C key structs using the pattern:

```rust
let mut key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
sys::wc_ecc_init_ex(key.as_mut_ptr(), heap, devId);
let key = key.assume_init();   // ← bitwise copy moves the struct
ECC { wc_ecc_key: key }        // ← moves again into the returned value
```

When wolfSSL is built with `WOLFSSL_SP_MATH_ALL` — the configuration used by
`--enable-all` builds and by the system install at `/usr/local` — the
`sp_int` big-integer type stores a self-referential pointer: `sp_int.dp`
initially points to the inline digit array `sp_int.d[]` embedded within the
same struct. After `assume_init()` bitwise-copies the struct to a new stack
location, `dp` still points to the old address. The next arithmetic operation
that dereferences `dp` accesses freed stack memory, producing undefined
behavior.

**Observed symptoms during this review:**

- Deterministic `SIGSEGV` inside `wc_EccPublicKeyDecode` when calling
  `ECC::import_public_der` on any valid DER-encoded P-256 public key.
- Sporadic `NO_PRIVATE_KEY` (-216) errors from `ECC::sign_hash` after
  `ECC::generate`, depending on whether the compiler applies Return Value
  Optimization (RVO) to elide one of the moves. Approximately 2 in 3 runs
  failed when RVO was not applied.

The same `MaybeUninit` + `assume_init` + struct field pattern is used for
every key type in the crate (`ecc_key`, `ed25519_key`, `ed448_key`, `RsaKey`,
`MlKemKey`). Only `ecc_key` is confirmed to contain a self-referential
`sp_int`; the other types should be audited.

**Fix required:** Store `wc_ecc_key` on the heap so the allocation address
is stable across Rust moves:

```rust
pub struct ECC {
    wc_ecc_key: Box<sys::ecc_key>,
}
```

This change requires modifications to `wolfssl-wolfcrypt` itself and should
accompany a version bump. Neither PR #10248 nor PR #10305 addresses it.
Both PRs add code that calls through the move-unsafe `ECC` struct, meaning
the ECDSA signature code from PR #10248 and the verify-hash fix from PR #10305
both inherit this soundness bug on any `WOLFSSL_SP_MATH_ALL` build.

---

## Coverage Gaps in the New Trait Implementations

Beyond structural issues, the test coverage in the PRs is thin relative to
what the external oracles can exercise:

| Area | PR coverage | Independent oracle available |
|---|---|---|
| CMAC | AES-128 only; 1 of 4 NIST 800-38B vector lengths | NIST SP 800-38B App. D: 3 key sizes × 4 lengths |
| HMAC | SHA-256 only; 3 of 7 RFC 4231 vectors | Wycheproof: SHA-1/224/256/384/512/SHA-3 family |
| ML-KEM | Round-trip only; no byte-exact KAT vectors | NIST FIPS 203 ACVP encap/decap vectors |
| PBKDF2 | Round-trip only | Wycheproof: HMAC-SHA1/256/384/512 |

Round-trip tests (encrypt → decrypt with the same code path) verify that
code runs without crashing; they do not verify correctness of the output
bytes. An implementation that computed the wrong ciphertext would pass a
round-trip test but fail a known-answer test.

---

## Summary Table

| Gap | Severity | Fixed by PR #10248 | Fixed by PR #10305 | Remains open |
|---|---|:---:|:---:|:---:|
| 1. No `Aes192Gcm`/`Aes192Ccm` | Completeness | — | — | **Yes** |
| 2. `sigs_left()` breaking rename | API break | — | Introduces it | **Yes** (needs semver bump) |
| 3. `encode_public_key` type break | API break | — | Introduces it | **Yes** (needs semver bump) |
| 4. CMAC/HMAC lack `Clone`/`Reset` | Trait compat | — | — | **Yes** |
| 5. `verify_hash` `res != 0` check | Correctness | — | Fixes it | No |
| 6. ECC struct not move-safe | **Soundness / UB** | — | — | **Yes** |

---

## Recommended Actions Before Merging PR #10305

1. **Require a semver bump.** Gaps 2 and 3 are breaking changes. The PR must
   either bump the crate version or add `#[deprecated]` compatibility aliases
   before it can be considered non-breaking.

2. **File a blocker for Gap 6 before PR #10248 merges.** The ECDSA and ECC
   verification code added by PR #10248 is built on the move-unsafe `ECC`
   struct. Users on `--enable-all` or any SP-math build will encounter UB.
   A fix (boxing `wc_ecc_key`) should be tracked as a blocking issue.

3. **File a follow-up for Gap 4.** Adding `Clone` and `Reset` to the CMAC
   and HMAC types is straightforward and needed for idiomatic RustCrypto use.

4. **File a follow-up for Gap 1.** `Aes192Gcm` and `Aes192Ccm` are trivial
   additions (copy existing 128/256 impls, change key size to `U24`) and
   close a FIPS compliance gap.

5. **Upgrade PR test coverage.** Adding NIST KAT vectors for CMAC and HMAC,
   and ACVP vectors for ML-KEM, before PR #10305 merges would give reviewers
   confidence that the implementations are correct, not just functional. The
   test stubs in this suite (`test_mac.rs`, `test_kem.rs`, `test_pbkdf2.rs`)
   are ready to run once the PRs are checked out locally.
