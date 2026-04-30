# Crate Inventory (from session research, confirmed by INVENTORY agent run)

## Current local tree (v1.2.0, pre-PR-#10248)

### Modules with RustCrypto trait impls:
- random.rs: RNG → rand_core::TryRng, TryCryptoRng
- aes.rs: Aes128/192/256 EcbEnc/Dec → cipher::{KeySizeUser,BlockSizeUser,KeyInit,BlockEncrypt/Decrypt}
           Aes128/192/256 Ctr → cipher::{KeySizeUser,IvSizeUser,KeyIvInit,StreamCipher} [cfg: aes_ctr]
           Aes128/192/256 Ofb → cipher::KeySizeUser only confirmed; IvSizeUser/KeyIvInit/StreamCipher behind [cfg: aes_ofb]
           Aes128/192/256 CbcEnc/Dec → cipher::{KeySizeUser,BlockSizeUser} + backend [cfg: aes_cbc]
           Aes128/256 Gcm → aead::{KeySizeUser,AeadCore,KeyInit,AeadInPlace} [cfg: aes_gcm]
           Aes128/256 Ccm → aead::{KeySizeUser,AeadCore,KeyInit,AeadInPlace} [cfg: aes_ccm]
- chacha20_poly1305.rs: ChaCha20Poly1305Aead, XChaCha20Poly1305Aead → aead::{KeySizeUser,AeadCore,KeyInit,AeadInPlace}

### Modules WITHOUT RustCrypto trait impls (yet):
- sha.rs: SHA, SHA224, SHA256, SHA384, SHA512, SHA3_*, SHAKE128/256 — no digest::Digest
- hmac.rs: HMAC — no digest::Mac
- cmac.rs: CMAC — no digest::Mac
- ecc.rs: ECC — no signature::*
- ed25519.rs: ED25519Key — no signature::*
- ed448.rs: ED448Key — no signature::*
- rsa.rs: RSA — no signature::*
- mlkem.rs: MlKem — no kem::*
- hkdf.rs, kdf.rs: custom APIs only

### Modules added by PR #10248 (merged, NOT in local tree):
- src/sha_digest.rs — digest::Digest for all SHA types
- src/ecdsa.rs — signature::{Signer,Verifier} for P-256/384/521
- src/rsa_pkcs1v15.rs — signature traits for RSA

### Modules added by PR #10305 (open, NOT in local tree):
- src/cmac_mac.rs — digest::Mac for CMAC AES-128/192/256
- src/hmac_mac.rs — digest::Mac for HMAC-SHA*
- src/mlkem_kem.rs — kem::Kem for ML-KEM-512/768/1024
- src/pbkdf2_password_hash.rs — password_hash::PasswordHasher for PBKDF2

### Notable gaps regardless of PRs:
- No Aes192Gcm or Aes192Ccm
- No blake2 digest traits
- No HKDF standard trait (no such widely-used trait exists yet)
