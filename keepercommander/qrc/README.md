# QRC (Quantum Resistant Cryptography)

Hybrid post-quantum encryption for Keeper Commander using **ECDH-P256** + **ML-KEM-1024** to protect against future quantum computing threats.

## Why QRC?

Quantum computers threaten current encryption:
- **Shor's Algorithm**: Can break RSA and ECC in polynomial time
- **Harvest Now, Decrypt Later**: Adversaries may store encrypted data today to decrypt when quantum computers mature

QRC provides **defense-in-depth** by combining classical and post-quantum cryptography, ensuring data remains secure even if one algorithm is compromised.

## How It Works

### Hybrid Key Exchange

```
┌─────────────────────────────────────────────────────────────────┐
│                     QRC Hybrid Encryption                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Client                                Server                  │
│     │                                     │                     │
│     │──── ECDH (P-256) ──────────────────►│                     │
│     │     ephemeral EC key                │                     │
│     │                                     │                     │
│     │──── ML-KEM-1024 ───────────────────►│                     │
│     │     encapsulated secret             │                     │
│     │                                     │                     │
│     ├─────────────────────────────────────┤                     │
│     │  HKDF-SHA256(EC_secret ║ KEM_secret)│                     │
│     │              ↓                      │                     │
│     │         AES-256 Key                 │                     │
│     ├─────────────────────────────────────┤                     │
│     │                                     │                     │
│     │──── AES-GCM encrypted payload ─────►│                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

1. **ECDH-P256**: Client generates ephemeral EC keypair, exchanges with server's static EC public key
2. **ML-KEM-1024**: Client encapsulates a shared secret using server's ML-KEM public key (NIST FIPS 203)
3. **HKDF**: Both secrets are concatenated and derived into a single AES-256 key
4. **AES-GCM**: Transmission key is encrypted with the derived key

## Server Support

| Server | QRC Status | Key ID |
|--------|------------|--------|
| `keepersecurity.com` | Enabled | 136 |
| `qa.keepersecurity.com` | Enabled | 107 |
| `staging.keepersecurity.com` | Enabled | 124 |
| `dev.keepersecurity.com` | EC Only | — |
| GovCloud | ⏳ Pending | 148/160 |
| IL5 | ⏳ Pending | 172/186 |

## Fallback Behavior

QRC gracefully falls back to EC-only encryption when:

| Trigger | Behavior |
|---------|----------|
| Python < 3.11 | Skip QRC, use EC |
| `keeper-mlkem` not installed | Skip QRC, use EC |
| Server returns key mismatch | Disable QRC for session, retry with EC |
| ML-KEM encapsulation error | Disable QRC for session, retry with EC |
| Server HTTP 400/500 during QRC | Disable QRC for session, retry with EC |

All fallbacks are logged and transparent—connections continue uninterrupted.

## Requirements

- **Python 3.11+** (required for ML-KEM C extension)
- **keeper-mlkem** package ([PyPI](https://pypi.org/project/keeper-mlkem/))

The `keeper-mlkem` package provides NIST FIPS 203 ML-KEM implementation with optimized C extensions for performance. It's installed automatically as a Commander dependency.

## Implementation

```
qrc/
├── qrc_crypto.py    # Hybrid encryption: ECDH + ML-KEM + HKDF
└── README.md        # This file

External dependency:
└── keeper-mlkem     # ML-KEM-1024 implementation (PyPI package)
```

## Security Properties

| Property | Protection |
|----------|------------|
| **Quantum Resistance** | ML-KEM-1024 protects against Shor's algorithm |
| **Hybrid Defense** | If ML-KEM or ECDH is broken, the other still protects |
| **Forward Secrecy** | Ephemeral EC keys ensure past sessions stay secure |
| **Constant-Time** | C extension avoids timing side-channels |

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) - Hybrid Public Key Encryption (HPKE)
- [keeper-mlkem](https://pypi.org/project/keeper-mlkem/) - ML-KEM Python package
