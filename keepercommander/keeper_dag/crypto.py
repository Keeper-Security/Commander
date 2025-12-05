from __future__ import annotations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
from typing import Optional, Union


def encrypt_aes(data: bytes, key: bytes, iv: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    iv = iv or os.urandom(12)
    enc = aesgcm.encrypt(iv, data, None)
    return iv + enc


def decrypt_aes(data: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(data[:12], data[12:], None)


def decrypt_aes_fancy(encrypted_data, key: bytes):
    aesgcm = AESGCM(key)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext


def bytes_to_base64(b: Union[str, bytes]) -> str:

    if isinstance(b, str):
        b = b.encode()

    return base64.b64encode(b).decode()


def urlsafe_str_to_bytes(s: str) -> bytes:
    b = base64.urlsafe_b64decode(s + '==')
    return b


def str_to_bytes(s: str) -> bytes:
    b = base64.b64decode(s + '==')
    return b


def bytes_to_urlsafe_str(b: Union[str, bytes]) -> str:
    """
    Convert bytes to a URL-safe base64 encoded string.

    Args:
        b (bytes): The bytes to be encoded.

    Returns:
        str: The URL-safe base64 encoded representation of the input bytes.
    """
    if isinstance(b, str):
        b = b.encode()

    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def bytes_to_str(b: bytes) -> str:
    """
    Convert bytes to a URL-safe base64 encoded string.

    Args:
        b (bytes): The bytes to be encoded.

    Returns:
        str: The URL-safe base64 encoded representation of the input bytes.
    """
    return base64.b64encode(b).decode().rstrip('=')


def generate_random_bytes(length: int) -> bytes:
    return os.urandom(length)


def generate_uid_bytes(length: int = 16) -> bytes:
    return generate_random_bytes(length)


def generate_uid_str(uid_bytes: Optional[bytes] = None) -> str:
    if uid_bytes is None:
        uid_bytes = generate_uid_bytes()
    return bytes_to_urlsafe_str(uid_bytes)
