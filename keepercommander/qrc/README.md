# QRC (Quantum Resistant Cryptography)

Hybrid encryption using ECDH-P256 + ML-KEM-768 for quantum-resistant security in Keeper Commander.

## Prerequisites

- **Python 3.11+** (QRC only works on Python 3.11 and above)
- **C compiler** for building the fast math extension
- **Install**: `pip install -e .` (compiles `fastmathmodule.c` for your platform)

## Implementation: ML-KEM-768

- **Algorithm**: ML-KEM-768 (NIST standardized post-quantum cryptography)
- **Key Size**: 1184 bytes (exact requirement)
- **Security Level**: Equivalent to AES-192

## How QRC Works

### 1. Server Detection & Key Selection
```python
# rest_api.py detects server and gets appropriate key ID
qrc_key_id = get_qrc_mlkem_key_id(server_url)
# Returns: 100 (dev), 101 (qa), 102 (staging), 103 (prod), 104/105 (gov)

# Check if we have the ML-KEM key for this server
if qrc_key_id in SERVER_PUBLIC_KEYS:
    use_qrc = True
else:
    use_qrc = False  # Fallback to EC encryption
```

### 2. QRC Confirmation Check
```python
# Only proceed with QRC if:
if context.server_key_id >= 100 and isinstance(server_public_key, bytes):
    # QRC confirmed - proceed with hybrid encryption
```

### 3. ECDH (Existing EC Implementation)
```python
# Reuse existing EC key or generate new one
if not hasattr(context, 'client_ec_private_key'):
    context.client_ec_private_key = crypto.generate_ec_key()[0]

# Standard ECDH exchange (same as before QRC)
ec_shared_secret = client_ec_private_key.exchange(ec.ECDH(), server_ec_public_key)
```

### 4. ML-KEM Using Our Package
```python
# Import our ML-KEM implementation
from .mlkem.mlkem_core import MLKEM_768_PARAMETERS, ML_KEM

# Extract and validate 1184-byte key
raw_key = _extract_raw_key(server_mlkem_public_key)  # Must be exactly 1184 bytes

# Perform ML-KEM encapsulation
ml_kem = ML_KEM(MLKEM_768_PARAMETERS, fast=True)
mlkem_shared_secret, mlkem_encapsulation = ml_kem.encaps(raw_key)
```

### 5. Hybrid Key Derivation
```python
# Combine both secrets
combined_secret = ec_shared_secret + mlkem_shared_secret

# Hash the ML-KEM encapsulation
mlkem_hash = Hash(SHA256())
mlkem_hash.update(mlkem_encapsulation)
mlkem_ciphertext_hash = mlkem_hash.finalize()

# Create context for HKDF
context_info = (
    QRC_CIPHER_SUITE.encode('utf-8') +     # "HPKE_ML-KEM-768_ECDH-P256_HKDF-SHA256_AES-GCM-256"
    server_ec_public_key_bytes +           # Server's EC public key
    client_ec_public_key_bytes +           # Client's EC public key  
    mlkem_ciphertext_hash +                # Hash of ML-KEM ciphertext
    QRC_MESSAGE_VERSION.to_bytes(1, 'big') # Version (1)
)

# Derive AES key using HKDF-SHA256
hkdf = HKDF(algorithm=SHA256(), length=32, salt=b'\x00' * 32, info=context_info)
aes_key = hkdf.derive(combined_secret)
```

### 6. AES Encryption & Proto Message
```python
# Encrypt transmission key with derived AES key
encrypted_data = crypto.encrypt_aes_v2(transmission_key, aes_key)

# Add QRC fields to API request proto
api_request.qrcMessageKey.clientEcPublicKey = client_ec_public_key_bytes
api_request.qrcMessageKey.mlKemEncapsulatedKey = mlkem_encapsulation  
api_request.qrcMessageKey.data = encrypted_data
api_request.qrcMessageKey.msgVersion = QRC_MESSAGE_VERSION  # 1
api_request.qrcMessageKey.ecKeyId = 7  # Always use EC key 7
```

## Fallback to EC Encryption

QRC falls back to standard EC encryption when:

### Client-Side Fallback (Immediate)
- **Python < 3.11**: QRC not attempted
- **C extension missing**: ML-KEM implementation unavailable  
- **Invalid key size**: Server ML-KEM key is not exactly 1184 bytes
- **ML-KEM failure**: Encapsulation fails

### Server-Side Fallback (After Request)
- **400 error + QRC key ID ≥ 100**: Server can't decrypt QRC message
- **Any 400 error with QRC**: Server doesn't support QRC

```python
# Fallback logic in rest_api.py
except Exception as e:
    logging.warning(f"QRC encryption failed ({e}), falling back to EC encryption")
    context.server_key_id = 7  # Switch to EC key
    server_public_key = SERVER_PUBLIC_KEYS[7]

# Server error fallback  
elif rs.status_code == 400:
    if context.server_key_id >= 100:
        logging.warning("QRC request failed, falling back to EC encryption")
        context.server_key_id = 7
        run_request = True  # Retry with EC
```

## Error Cases

| Error | Cause | Action |
|-------|-------|--------|
| `ImportError` | C extension not compiled | Fallback to EC |
| `ValueError` | Key size ≠ 1184 bytes | Fallback to EC |
| `RuntimeError` | ML-KEM encapsulation failed | Fallback to EC |
| `400 + key_id ≥ 100` | Server QRC decryption failed | Retry with EC |
| `Python < 3.11` | Version check failed | Use EC from start |

## File Structure

```
qrc/
├── qrc_crypto.py          # Main QRC interface & key management
├── mlkem/                 # Our ML-KEM-768 implementation
│   ├── mlkem_core.py      # ML-KEM algorithm & parameter sets
│   ├── mlkem_math.py      # Finite field & polynomial math
│   ├── mlkem_auxiliary.py # Crypto utilities & NTT operations
│   └── fastmathmodule.c   # C extension for performance
└── README.md
```

## Key Advantages

- **Quantum resistance**: Protected against future quantum computers
- **Hybrid security**: Two independent cryptographic systems
- **Graceful fallback**: Always maintains connectivity
- **Performance**: C extension + session key reuse