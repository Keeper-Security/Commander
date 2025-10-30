#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import logging
import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from .. import crypto

ML_KEM_768 = "ML-KEM-768"
QRC_MESSAGE_VERSION = 1
QRC_CIPHER_SUITE = "HPKE_ML-KEM-768_ECDH-P256_HKDF-SHA256_AES-GCM-256"

logger = logging.getLogger(__name__)

def _extract_raw_key(public_key: bytes) -> bytes:
    if public_key.startswith(b'-----BEGIN PUBLIC KEY-----'):
        pem_lines = public_key.decode('utf-8').strip().split('\n')
        pem_data = ''.join(pem_lines[1:-1])
        der_data = base64.b64decode(pem_data)
        if len(der_data) < 1184:
            raise ValueError(f"PEM key too short: {len(der_data)} bytes, expected ≥1184")
        raw_key = der_data[-1184:]
        logger.debug(f"Extracted {len(raw_key)} byte raw key from {len(der_data)} byte PEM")
        return raw_key
    return public_key

def encrypt_qrc(transmission_key: bytes, client_ec_private_key: ec.EllipticCurvePrivateKey, server_ec_public_key: ec.EllipticCurvePublicKey, server_mlkem_public_key: bytes) -> dict:
    try:
        ec_shared_secret = client_ec_private_key.exchange(ec.ECDH(), server_ec_public_key)
        logger.debug(f"ECDH completed: {len(ec_shared_secret)} byte shared secret")

        mlkem_shared_secret, mlkem_encapsulation = _mlkem_encapsulation(server_mlkem_public_key)
        logger.debug(f"ML-KEM completed: {len(mlkem_shared_secret)} byte secret, {len(mlkem_encapsulation)} byte encapsulation")
        
        client_ec_public_key_bytes = crypto.unload_ec_public_key(client_ec_private_key.public_key())
        server_ec_public_key_bytes = crypto.unload_ec_public_key(server_ec_public_key)
        aes_key = _combine_secrets_hkdf(ec_shared_secret, mlkem_shared_secret, server_ec_public_key_bytes, client_ec_public_key_bytes, mlkem_encapsulation)
        logger.debug(f"HKDF completed: derived {len(aes_key)} byte AES key")
        
        encrypted_data = crypto.encrypt_aes_v2(transmission_key, aes_key)
        logger.debug(f"AES-GCM completed: {len(encrypted_data)} byte ciphertext")
       
        return {
            'client_ec_public_key': client_ec_public_key_bytes,
            'ml_kem_encapsulated_key': mlkem_encapsulation,
            'data': encrypted_data,
            'msg_version': QRC_MESSAGE_VERSION
        }
    except Exception as e:
        logger.error(f"QRC encryption failed: {e}")
        raise

def _mlkem_encapsulation(server_mlkem_public_key: bytes) -> Tuple[bytes, bytes]:
    try:
        #from .mlkem import MLKEM_768_PARAMETERS, ML_KEM
        from mlkem import MLKEM_768_PARAMETERS, ML_KEM
        
        raw_key = _extract_raw_key(server_mlkem_public_key)
        if len(raw_key) != 1184:
            raise ValueError(f"Invalid ML-KEM-768 key size: {len(raw_key)} bytes (expected 1184)")
        
        ml_kem = ML_KEM(MLKEM_768_PARAMETERS)
        return ml_kem.encaps(raw_key)
    except ImportError as e:
        logger.error(f"ML-KEM implementation not available: {e}")
        raise RuntimeError(f"ML-KEM implementation not available: {e}")
    except Exception as e:
        logger.error(f"ML-KEM encapsulation failed: {e}")
        raise RuntimeError(f"ML-KEM encapsulation error: {e}")

def _combine_secrets_hkdf(ec_secret: bytes, mlkem_secret: bytes, server_ec_pub: bytes, client_ec_pub: bytes, mlkem_encapsulation: bytes) -> bytes:
    combined_secret = ec_secret + mlkem_secret
    digest = Hash(SHA256(), backend=crypto._CRYPTO_BACKEND)
    digest.update(mlkem_encapsulation)
    mlkem_ciphertext_hash = digest.finalize()

    context_info = (
        b'' + 
        QRC_CIPHER_SUITE.encode('utf-8') +
        server_ec_pub +
        client_ec_pub +
        mlkem_ciphertext_hash +
        QRC_MESSAGE_VERSION.to_bytes(1, 'big')
    )
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=context_info,
        backend=crypto._CRYPTO_BACKEND
    )

    derived_key = hkdf.derive(combined_secret)
    return derived_key