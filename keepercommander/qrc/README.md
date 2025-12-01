# QRC (Quantum Resistant Cryptography)

Hybrid post-quantum encryption for Keeper Commander using **ECDH-P256** + **ML-KEM-768** to protect against future quantum computing threats.

## Overview

QRC enhances Keeper's API security by combining traditional elliptic curve cryptography with NIST-standardized post-quantum ML-KEM (Module-Lattice-based Key Encapsulation Mechanism). This hybrid approach ensures both current security and future quantum resistance.

## Key Features

- **Hybrid Encryption**: Combines ECDH-P256 and ML-KEM-768 for dual-layer protection
- **Post-Quantum Ready**: Uses NIST FIPS 203 standardized ML-KEM algorithm
- **Graceful Fallback**: Automatically falls back to EC-only encryption when QRC unavailable
- **Performance Optimized**: Uses C extension via `keeper-mlkem` package for fast cryptographic operations

## Requirements

- **Python 3.11+** (required for ML-KEM implementation)
- **keeper-mlkem** package (installed automatically with Commander dependencies)

## Current Implementation

### ML-KEM Variant
- **Current**: ML-KEM-768 (1184-byte keys, AES-192 equivalent security)
- **Future**: Can transition to ML-KEM-1024 (1568-byte keys) when backend supports it

### Server Support

| Server | QRC Status | Key ID | Notes |
|--------|------------|--------|-------|
| `dev.keepersecurity.com` | ✅ Enabled | 100 | Only dev has ML-KEM key currently |
| `qa.keepersecurity.com` | ⏳ EC Only | 7 | Falls back to EC encryption |
| `staging.keepersecurity.com` | ⏳ EC Only | 7 | Falls back to EC encryption |
| `keepersecurity.com` | ⏳ EC Only | 7 | Falls back to EC encryption |
| GovCloud servers | ⏳ EC Only | 7 | Falls back to EC encryption |

**Note**: As additional servers add ML-KEM keys, they'll automatically use QRC. The implementation supports key IDs 100-105 for different environments.

## How It Works

### 1. **Key Determination**
On first API call, `RestApiContext` determines which encryption to use:
- Checks server URL and Python version
- Sets `qrc_key_id` (100+ for QRC) or uses `server_key_id` (7 for EC-only)
- Resets on logout or server change to re-determine on next login

### 2. **Hybrid Key Encapsulation**
When QRC is available:
- **ECDH**: Client generates ephemeral EC key, performs ECDH with server's EC public key
- **ML-KEM**: Encapsulates shared secret using server's ML-KEM public key
- **Combine**: Both secrets are combined and derived using HKDF-SHA256

### 3. **Cipher Suite**
```
HPKE_ML-KEM-768_ECDH-P256_HKDF-SHA256_AES-GCM-256
```
- ML-KEM-768 for post-quantum KEM
- ECDH-P256 for classical key exchange
- HKDF-SHA256 for key derivation
- AES-256-GCM for encryption

### 4. **Protocol Message**
QRC adds these fields to API requests:
- `clientEcPublicKey`: Client's ephemeral EC public key
- `mlKemEncapsulatedKey`: ML-KEM ciphertext (encapsulated shared secret)
- `data`: AES-encrypted transmission key
- `ecKeyId`: Always 7 (EC key for ECDH)
- `msgVersion`: Protocol version (1)

## Fallback Behavior

QRC automatically falls back to standard EC encryption when:

### Client-Side Triggers
- Python version < 3.11
- `keeper-mlkem` package not installed
- Invalid ML-KEM key size from server
- ML-KEM encapsulation error

### Server-Side Triggers
- Server returns HTTP 400 with QRC key mismatch
- Server doesn't support QRC for that environment

All fallbacks are logged and transparent to the user—connections continue uninterrupted using EC encryption.

## Implementation Files

```
qrc/
├── qrc_crypto.py          # QRC encryption interface & hybrid key derivation
├── mlkem/                 # Imports from keeper-mlkem package
│   ├── __init__.py        # Package exports
│   ├── mlkem_core.py      # ML-KEM implementation (768/1024 variants)
│   └── fastmath.so        # C extension (compiled per platform)
└── README.md              # This file
```

**External Package**: The `keeper-mlkem` library is published separately to PyPI and provides the ML-KEM cryptographic primitives with optimized C extensions.

## Migration Path

The implementation is designed for easy transition to ML-KEM-1024:

1. **Client-side**: Change `MLKEM_768_PARAMETERS` → `MLKEM_1024_PARAMETERS` in `qrc_crypto.py`
2. **Server-side**: Backend provisions 1568-byte ML-KEM-1024 keys
3. **Backward compatible**: Older clients fall back to EC; newer clients use ML-KEM-1024

## Security Considerations

- **Quantum Resistance**: ML-KEM protects against Shor's algorithm (breaks RSA/ECC)
- **Hybrid Defense**: If either ML-KEM or ECDH is broken, the other still protects data
- **Side-Channel Protection**: C extension uses constant-time operations