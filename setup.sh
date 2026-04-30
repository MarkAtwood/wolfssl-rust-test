#!/usr/bin/env bash
# setup.sh — populate external/ with shallow clones of test vector repos.
# Idempotent: skips clones that already exist.
# Run once before: cargo test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p external

# wolfSSL/wychcheck — bundles NIST ACVP ML-KEM/ML-DSA vectors and RFC vectors
# (testvectors_acvp/, testvectors_rfc/)
if [ ! -d external/wychcheck ]; then
    echo "Cloning wolfSSL/wychcheck..."
    git clone --depth 1 https://github.com/wolfSSL/wychcheck external/wychcheck
    echo "  HEAD: $(git -C external/wychcheck rev-parse HEAD)" | tee -a audit/vector_commits.txt
else
    echo "external/wychcheck already present (skipping)"
fi

# google/wycheproof — all Wycheproof JSON test vectors (AEAD, HMAC, PBKDF2,
# ECDSA, RSA, ...). wychcheck lists this as a submodule but we clone directly
# — same content, no recursive submodule machinery needed.
if [ ! -d external/wycheproof ]; then
    echo "Cloning google/wycheproof..."
    git clone --depth 1 https://github.com/google/wycheproof external/wycheproof
    echo "  HEAD: $(git -C external/wycheproof rev-parse HEAD)" | tee -a audit/vector_commits.txt
else
    echo "external/wycheproof already present (skipping)"
fi

# wychcheck also lists usnistgov/ACVP-Server and google/boringssl as submodules
# but marks them update=none (reference-only, 900 MB+). Do NOT clone them.

echo ""
echo "Setup complete. Vector sources:"
echo "  external/wychcheck/testvectors_acvp/  -- NIST FIPS 203 ML-KEM ACVP vectors"
echo "  external/wychcheck/testvectors_rfc/   -- RFC 8032 EdDSA vectors"
echo "  external/wycheproof/testvectors_v1/   -- all Wycheproof JSON vectors"
echo ""
echo "To run all tests:"
echo "  cargo test"
echo ""
echo "If wolfSSL is not in the auto-detected location (~/WORK/wolfssl):"
echo "  WOLFSSL_PREFIX=/path/to/wolfssl cargo test"
