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
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from .. import crypto

QRC_MESSAGE_VERSION = 1
MLKEM_1024_KEY_SIZE = 1568
QRC_CIPHER_SUITE = "HPKE_ML-KEM-1024_ECDH-P256_HKDF-SHA256_AES-GCM-256"

logger = logging.getLogger(__name__)

def encrypt_qrc(transmission_key: bytes, client_ec_private_key: ec.EllipticCurvePrivateKey, server_ec_public_key: ec.EllipticCurvePublicKey, server_mlkem_public_key: bytes) -> dict:
    try:
        ec_shared_secret = client_ec_private_key.exchange(ec.ECDH(), server_ec_public_key)
        logger.debug(f"ECDH completed: {len(ec_shared_secret)} byte shared secret")

        mlkem_shared_secret, mlkem_encapsulation = _mlkem_encapsulation(server_mlkem_public_key)
        logger.debug(f"ML-KEM-1024 completed: {len(mlkem_shared_secret)} byte secret, {len(mlkem_encapsulation)} byte encapsulation")
        
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
    """Encapsulate using ML-KEM-1024. Returns: (shared_secret, ciphertext)"""
    try:
        from mlkem import MLKEM_1024_PARAMETERS, ML_KEM
        if len(server_mlkem_public_key) != MLKEM_1024_KEY_SIZE:
            raise ValueError(f"Invalid ML-KEM-1024 key size: {len(server_mlkem_public_key)} bytes")
        ml_kem = ML_KEM(MLKEM_1024_PARAMETERS)
        return ml_kem.encaps(server_mlkem_public_key)
    except ImportError as e:
        raise RuntimeError(f"ML-KEM implementation not available: {e}")
    except Exception as e:
        raise RuntimeError(f"ML-KEM encapsulation error: {e}")

def _combine_secrets_hkdf(ec_secret: bytes, mlkem_secret: bytes, server_ec_pub: bytes, client_ec_pub: bytes, mlkem_encapsulation: bytes) -> bytes:
    digest = Hash(SHA256(), backend=crypto._CRYPTO_BACKEND)
    digest.update(mlkem_encapsulation)
    mlkem_ciphertext_hash = digest.finalize()

    context_info = (
        QRC_CIPHER_SUITE.encode('utf-8') +
        server_ec_pub +
        client_ec_pub +
        mlkem_ciphertext_hash +
        QRC_MESSAGE_VERSION.to_bytes(1, 'big')
    )
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b'\x00' * 32,  # 32-byte zero salt to match server implementation
        info=context_info,
        backend=crypto._CRYPTO_BACKEND
    )
    return hkdf.derive(ec_secret + mlkem_secret)