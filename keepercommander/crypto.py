#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

_CRYPTO_BACKEND = default_backend()
_CURVE = ec.SECP256R1()


def pad_data(data):    # type: (bytes) -> bytes
    padder = PKCS7(16*8).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(data):     # type: (bytes) -> bytes
    unpadder = PKCS7(16*8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def get_random_bytes(length):
    return os.urandom(length)


def generate_rsa_key():
    private_key = rsa.generate_private_key(key_size=2048, public_exponent=0x10001, backend=_CRYPTO_BACKEND)
    return private_key, private_key.public_key()


def load_rsa_private_key(der_private_key, password=None):
    return serialization.load_der_private_key(der_private_key, password, _CRYPTO_BACKEND)


def load_rsa_public_key(der_public_key):
    return serialization.load_der_public_key(der_public_key, _CRYPTO_BACKEND)


def unload_rsa_private_key(private_key):
    return private_key.private_bytes(encoding=serialization.Encoding.DER,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=serialization.NoEncryption())


def unload_rsa_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.DER,
                                   format=serialization.PublicFormat.PKCS1)


def generate_ec_key():
    private_key = ec.generate_private_key(curve=_CURVE, backend=_CRYPTO_BACKEND)
    return private_key, private_key.public_key()


def load_ec_private_key(private_key):
    private_value = int.from_bytes(private_key, byteorder='big', signed=False)
    return ec.derive_private_key(private_value, _CURVE, _CRYPTO_BACKEND)


def load_ec_public_key(public_key):
    return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, public_key)


def unload_ec_private_key(private_key):
    private_value = private_key.private_numbers().private_value
    return private_value.to_bytes(length=32, byteorder='big', signed=False)


def unload_ec_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.X962,
                                   format=serialization.PublicFormat.UncompressedPoint)


def encrypt_aes_v1(data, key, iv=None, use_padding=True):
    iv = iv or os.urandom(16)
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(pad_data(data) if use_padding else data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_aes_v1(data, key, use_padding=True):
    iv = data[:16]
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
    return unpad_data(decrypted_data) if use_padding else decrypted_data


def encrypt_aes_v2(data, key, nonce=None):
    aesgcm = AESGCM(key)
    nonce = nonce or os.urandom(12)
    enc = aesgcm.encrypt(nonce, data, None)
    return nonce + enc


def decrypt_aes_v2(data, key):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(data[:12], data[12:], None)


def encrypt_rsa(data, rsa_key):
    return rsa_key.encrypt(data, PKCS1v15())


def decrypt_rsa(data, rsa_key):
    return rsa_key.decrypt(data, PKCS1v15())


def encrypt_ec(data, ec_public_key):
    e_private_key, e_public_key = generate_ec_key()
    shared_secret = e_private_key.exchange(ec.ECDH(), ec_public_key)
    digest = Hash(SHA256(), backend=_CRYPTO_BACKEND)
    digest.update(shared_secret)
    encryption_key = digest.finalize()
    return unload_ec_public_key(e_public_key) + encrypt_aes_v2(data, encryption_key)


def decrypt_ec(data, ec_private_key):
    ephemeral_public_key = load_ec_public_key(data[:65])
    shared_secret = ec_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    digest = Hash(SHA256(), backend=_CRYPTO_BACKEND)
    digest.update(shared_secret)
    encryption_key = digest.finalize()
    return decrypt_aes_v2(data[65:], encryption_key)


def derive_key_v1(password, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations, backend=_CRYPTO_BACKEND)
    return kdf.derive(password.encode('utf-8'))


def derive_keyhash_v1(password, salt, iterations):
    derived_key = derive_key_v1(password, salt, iterations)
    hf = Hash(SHA256(), backend=_CRYPTO_BACKEND)
    hf.update(derived_key)
    return hf.finalize()


def derive_keyhash_v2(domain, password, salt, iterations):
    kdf = PBKDF2HMAC(algorithm=SHA512(), length=64, salt=salt, iterations=iterations, backend=_CRYPTO_BACKEND)
    derived_key = kdf.derive((domain+password).encode('utf-8'))
    hf = HMAC(derived_key, SHA256(), backend=_CRYPTO_BACKEND)
    hf.update(domain.encode('utf-8'))
    return hf.finalize()


class AesStreamCryptor(abc.ABC):
    def __init__(self, is_encrypt, block_size):
        self.is_encrypt = is_encrypt
        self.block_size = block_size
        self.input_tail = None
        self.output_tail = None

    def update(self, in_data):
        if self.input_tail:
            in_data = self.input_tail + in_data
            self.input_tail = None
        tail = len(in_data) % self.block_size
        if tail != 0:
            self.input_tail = in_data[-tail:]
            in_data = in_data[:-tail]
        if len(in_data) == 0:
            return b''

        out_data = self.native_update(in_data)
        if self.is_encrypt:
            return out_data
        else:
            if self.output_tail:
                out_data = self.output_tail + out_data
                self.output_tail = None
            if len(out_data) > self.block_size:
                self.output_tail = out_data[-self.block_size:]
                return out_data[:-self.block_size]
            else:
                self.output_tail = out_data
                return b''

    def finish(self):
        if self.is_encrypt:
            out_data = self.native_update(pad_data(self.input_tail or b''))
            if len(out_data) > 0:
                if self.output_tail:
                    self.output_tail = self.output_tail + out_data
                else:
                    self.output_tail = out_data

        out_data = self.native_finish()

        if self.output_tail:
            out_data = self.output_tail + out_data
            self.output_tail = None

        if self.is_encrypt:
            return out_data
        else:
            return unpad_data(out_data)

    @abc.abstractmethod
    def native_update(self, data):  # type: (bytes) -> bytes
        pass

    @abc.abstractmethod
    def native_finish(self):        # type: () -> bytes
        pass


class AesStreamCryptorImpl(AesStreamCryptor):
    def __init__(self, is_encrypt, iv, key):
        super().__init__(is_encrypt, len(iv))
        cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
        self.cryptor = cipher.encryptor() if is_encrypt else cipher.decryptor()  # type: CipherContext

    def native_update(self, data):
        return self.cryptor.update(data)

    def native_finish(self):
        return self.cryptor.finalize()


def aes_v1_stream_decryptor(iv, key):
    return AesStreamCryptorImpl(False, iv, key)


def aes_v1_stream_encryptor(iv, key):
    return AesStreamCryptorImpl(True, iv, key)
