# QRC (Quantum Resistant Cryptography)

Hybrid post-quantum encryption for Keeper Commander using **ECDH-P256** + **ML-KEM-1024** to protect against future quantum computing threats.

## Overview

QRC enhances Keeper's API security by combining traditional elliptic curve cryptography with NIST-standardized post-quantum ML-KEM (Module-Lattice-based Key Encapsulation Mechanism). This hybrid approach ensures both current security and future quantum resistance.

## Key Features

- **Hybrid Encryption**: Combines ECDH-P256 and ML-KEM-1024 for dual-layer protection
- **Post-Quantum Ready**: Uses NIST FIPS 203 standardized ML-KEM algorithm
- **Graceful Fallback**: Automatically falls back to EC-only encryption when QRC unavailable
- **Performance Optimized**: Uses C extension via `keeper-mlkem` package for fast cryptographic operations

## Requirements

- **Python 3.11+** (required for ML-KEM implementation)
- **keeper-mlkem** package (installed automatically with Commander dependencies)

## Server Support

| Server | QRC Status | Key ID |
|--------|------------|--------|
| `dev.keepersecurity.com` | EC Only | 100 |
| `qa.keepersecurity.com` | ✅ Enabled | 107 |
| `staging.keepersecurity.com` | ✅ Enabled | 124 |
| `keepersecurity.com` | ✅ Enabled | 136 |
| GovCloud DEV | ⏳ Pending | 148 |
| GovCloud PROD | ⏳ Pending | 160 |
| IL5 DEV | ⏳ Pending | 172 |
| IL5 PROD | ⏳ Pending | 186 |

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
HPKE_ML-KEM-1024_ECDH-P256_HKDF-SHA256_AES-GCM-256
```
- ML-KEM-1024 for post-quantum KEM
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
│   ├── mlkem_core.py      # ML-KEM implementation (1024 variants)
│   └── fastmath.so        # C extension (compiled per platform)
└── README.md              # This file
```

**External Package**: The `keeper-mlkem` library is published separately to PyPI and provides the ML-KEM cryptographic primitives with optimized C extensions.

## Security Considerations

- **Quantum Resistance**: ML-KEM protects against Shor's algorithm (breaks RSA/ECC)
- **Hybrid Defense**: If either ML-KEM or ECDH is broken, the other still protects data
- **Side-Channel Protection**: C extension uses constant-time operations