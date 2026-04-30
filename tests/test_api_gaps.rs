//! API gap documentation for wolfssl-wolfcrypt Rust trait wrappers.
//!
//! This file documents known issues found during PR review. Each item is
//! either a commented code block that would fail to compile, or an
//! explanation of a runtime soundness or correctness problem.
//!
//! Referenced PRs: #10248 (digest/signature traits) and #10305
//! (mac/kem/password-hash traits plus bugfixes).
//!
//! Building this file verifies only that the documented gap items compile
//! (or fail to compile) as expected. See the inline comments for details.

mod common;

// Ensure wolfCrypt is initialized for any runtime checks below.
#[allow(dead_code)]
fn init() {
    common::init_wolfcrypt();
}

// ---------------------------------------------------------------------------
// Gap 1: Aes192Gcm and Aes192Ccm not exposed
// ---------------------------------------------------------------------------
//
// wolfCrypt supports AES-192 for GCM and CCM internally, but the Rust
// wrapper only exposes Aes128Gcm, Aes256Gcm, Aes128Ccm, Aes256Ccm.
//
// The following does not compile (E0432: unresolved import):
//
//   use wolfssl_wolfcrypt::aes::Aes192Gcm;
//   use wolfssl_wolfcrypt::aes::Aes192Ccm;
//
// Tracked as an API completeness gap, separate from PRs #10248/#10305.

// ---------------------------------------------------------------------------
// Gap 2: lms::Lms::sigs_left() renamed to has_sigs_left() in PR #10305
// ---------------------------------------------------------------------------
//
// PR #10305 renames Lms::sigs_left() → has_sigs_left() without:
//   - a deprecation alias for sigs_left()
//   - a semver version bump in Cargo.toml
//
// Before PR #10305, `sigs_left()` compiles and runs.
// After PR #10305, calling `sigs_left()` fails to compile:
//
//   lms.sigs_left()  // E0599 after PR: no method named `sigs_left`
//
// This is a breaking change that must accompany a semver minor or major bump.

// ---------------------------------------------------------------------------
// Gap 3: mlkem::MlKem::encode_public_key return type changed in PR #10305
// ---------------------------------------------------------------------------
//
// PR #10305 changes encode_public_key from Result<usize, i32> (bytes written)
// to Result<(), i32>. Callers that use the byte count fail after the PR:
//
//   let n: usize = key.encode_public_key(&mut buf)?;  // type error after PR
//
// Breaking change — no deprecation path provided.

// ---------------------------------------------------------------------------
// Gap 4: CMAC and HMAC Mac types lack Clone and Reset
// ---------------------------------------------------------------------------
//
// After PR #10305 adds digest::Mac impls, CMAC/HMAC types still do not
// implement Clone or Reset, limiting interoperability with RustCrypto:
//
//   let mac2 = mac.clone();  // E0277: doesn't implement Clone
//   mac.reset();             // E0277: doesn't implement Reset (if bound)

// ---------------------------------------------------------------------------
// Gap 5: ecc::ECC::verify_hash uses `res != 0` instead of `res == 1`
// ---------------------------------------------------------------------------
//
// wolfCrypt's wc_ecc_verify_hash() writes 1 into `res` for a valid signature
// and 0 for invalid. The current Rust wrapper returns `Ok(res != 0)`.
// If wc_ecc_verify_hash() ever stores a non-zero, non-1 value in `res`
// (e.g., an error-like sentinel), the wrapper incorrectly returns Ok(true).
// The correct check is `Ok(res == 1)`. PR #10305 fixes this.
//
// NOTE: A runtime test confirming this behavior would require calling
// ECC::verify_hash. However, wolfssl-wolfcrypt initializes ECC structs with
// MaybeUninit::uninit() on the stack followed by wc_ecc_init_ex(), then
// moves the struct via assume_init(). When wolfSSL is built with
// WOLFSSL_SP_MATH_ALL (as the system install at /usr/local is), the sp_int
// type stores a self-referential pointer (dp → inline d[]). Moving the
// struct invalidates that pointer, causing UB. Observed symptoms include
// SIGSEGV in EccPublicKeyDecode (with import_public_der) and sporadic
// NO_PRIVATE_KEY (-216) failures from sign_hash (with generate).
//
// This is documented as Gap 6 below.
//
// To reproduce the `res != 0` risk manually:
//   1. Land PR #10305 (which changes the check to `res == 1`).
//   2. Build wolfssl with a patched wc_ecc_verify_hash that writes 2 for
//      valid signatures to demonstrate the difference in behavior.

// ---------------------------------------------------------------------------
// Gap 6: ECC struct is not move-safe with WOLFSSL_SP_MATH_ALL
// ---------------------------------------------------------------------------
//
// wolfssl-wolfcrypt initializes all C key structs (ecc_key, etc.) using a
// pattern of:
//   let mut key: MaybeUninit<sys::ecc_key> = MaybeUninit::uninit();
//   sys::wc_ecc_init_ex(key.as_mut_ptr(), ...);
//   let key = key.assume_init();  // ← moves the struct
//   ECC { wc_ecc_key: key }       // ← moves again into return value
//
// When wolfSSL is built with WOLFSSL_SP_MATH_ALL (confirmed for the system
// install), sp_int stores a self-referential dp pointer that initially points
// to the inline d[] array within the struct. Bitwise-copying (moving) the
// struct leaves dp pointing to the old address, causing UB on the next
// arithmetic operation.
//
// Observed: SIGSEGV in ECC::import_public_der (deterministic) and sporadic
// NO_PRIVATE_KEY failures in ECC::generate + sign_hash (RVO-dependent).
//
// Fix: ECC should store wc_ecc_key on the heap (Box<wc_ecc_key>) so that
// the allocated address is stable across moves. This requires changes to the
// wolfssl-wolfcrypt crate itself, not the test suite.
//
// This is a soundness issue independent of PRs #10248 and #10305.
