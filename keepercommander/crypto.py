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

import io
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, GCM
from cryptography.hazmat.primitives.hashes import Hash, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

_CRYPTO_BACKEND = default_backend()
_CURVE = ec.SECP256R1()


def pad_data(data):    # type: (bytes) -> bytes
    padder = PKCS7(16*8).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(data):     # type: (bytes) -> bytes
    unpadder = PKCS7(16*8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def get_random_bytes(length):
    return secrets.token_bytes(length)


def generate_rsa_key():
    private_key = rsa.generate_private_key(key_size=2048, public_exponent=0x10001, backend=_CRYPTO_BACKEND)
    return private_key, private_key.public_key()


def load_rsa_private_key(der_private_key, password=None):
    return serialization.load_der_private_key(der_private_key, password, _CRYPTO_BACKEND)


def load_rsa_public_key(der_public_key):
    return serialization.load_der_public_key(der_public_key, _CRYPTO_BACKEND)


def unload_rsa_private_key(private_key):
    return private_key.private_bytes(encoding=serialization.Encoding.DER,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
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
    iv = iv or get_random_bytes(16)
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    encrypter = cipher.encryptor()
    encrypted_data = encrypter.update(pad_data(data) if use_padding else data) + encrypter.finalize()
    return iv + encrypted_data


def decrypt_aes_v1(data, key, use_padding=True):
    iv = data[:16]
    cipher = Cipher(AES(key), CBC(iv), backend=_CRYPTO_BACKEND)
    decrypter = cipher.decryptor()
    decrypted_data = decrypter.update(data[16:]) + decrypter.finalize()
    return unpad_data(decrypted_data) if use_padding else decrypted_data


def encrypt_aes_v2(data, key, nonce=None):
    nonce = nonce or get_random_bytes(12)
    cipher = Cipher(AES(key), GCM(nonce), backend=_CRYPTO_BACKEND)
    encrypter = cipher.encryptor()
    encrypted_data = encrypter.update(data) + encrypter.finalize()
    return nonce + encrypted_data + encrypter.tag


def decrypt_aes_v2(data, key):
    nonce = data[:12]
    cipher = Cipher(AES(key), GCM(nonce), backend=_CRYPTO_BACKEND)
    decrypter = cipher.decryptor()
    decrypted_data = decrypter.update(data[12:-16]) + decrypter.finalize_with_tag(data[-16:])
    return decrypted_data


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


def hmac_sha512(key, data):
    hf = HMAC(key, SHA512(), backend=_CRYPTO_BACKEND)
    hf.update(data)
    return hf.finalize()


class _StreamCrypter(io.RawIOBase):
    def __init__(self):
        super().__init__()
        self.key = b''
        self.is_gcm = False
        self.is_encrypt = False
        self.bytes_read = 0
        self._base_stream = None
        self.crypter = None
        self.is_eof = False
        self.in_buffer = None
        self.out_buffer = None
        self.in_buffer_pos = 0
        self.out_buffer_pos = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.in_buffer = None
        self.out_buffer = None
        self.crypter = None
        if self._base_stream:
            if hasattr(self._base_stream, '__exit__'):
                self._base_stream.__exit__(exc_type, exc_val, exc_tb)
            elif hasattr(self._base_stream, 'close'):
                self._base_stream.close()
            self._base_stream = None

    def set_stream(self, stream, for_encrypt):
        self.in_buffer = memoryview(bytearray(10240))
        self.in_buffer_pos = 0
        self.out_buffer = memoryview(bytearray(10240))
        self.out_buffer_pos = 0
        self.is_encrypt = for_encrypt
        self.bytes_read = 0
        if stream:
            self.is_eof = False
            if self.is_gcm:
                if self.is_encrypt:
                    nonce = get_random_bytes(12)
                    self.out_buffer[self.out_buffer_pos:self.out_buffer_pos + len(nonce)] = nonce
                    self.out_buffer_pos += len(nonce)
                else:
                    nonce = stream.read(12)
                    self.bytes_read += len(nonce)
                cipher = Cipher(AES(self.key), GCM(nonce), backend=_CRYPTO_BACKEND)
            else:
                if self.is_encrypt:
                    iv = get_random_bytes(16)
                    self.out_buffer[self.out_buffer_pos:self.out_buffer_pos + len(iv)] = iv
                    self.out_buffer_pos += len(iv)
                else:
                    iv = stream.read(16)
                    self.bytes_read += len(iv)
                cipher = Cipher(AES(self.key), CBC(iv), backend=_CRYPTO_BACKEND)
            self.crypter = cipher.encryptor() if self.is_encrypt else cipher.decryptor()
            self._base_stream = stream
        else:
            self.is_eof = True
        return self

    def closed(self):
        return self._base_stream is not None

    def close(self):
        self.__exit__(None, None, None)

    def readinto(self, buffer):
        buffer_len = 0
        mv = memoryview(buffer)
        while buffer_len < len(buffer):
            if self.out_buffer_pos == 0:
                if self._base_stream and not self.is_eof:
                    view = self.in_buffer[self.in_buffer_pos:len(self.in_buffer) - self.in_buffer_pos]
                    bytes_read = self._base_stream.readinto(view)
                    self.bytes_read += bytes_read
                    self.is_eof = bytes_read == 0
                    self.in_buffer_pos += bytes_read
                to_crypt = max(self.in_buffer_pos - 16, 0)
                if not self.is_gcm:
                    rem = to_crypt % 16
                    if rem != 0:
                        to_crypt -= rem
                bytes_left = len(self.out_buffer) - self.out_buffer_pos
                to_crypt = min(to_crypt, bytes_left - (16 if self.is_encrypt else 0))
                crypted = None
                if to_crypt > 0:
                    crypted = self.crypter.update(self.in_buffer[0:to_crypt])
                    if self.in_buffer_pos > to_crypt:
                        self.in_buffer[0:self.in_buffer_pos - to_crypt] = self.in_buffer[to_crypt: self.in_buffer_pos]
                        self.in_buffer_pos -= to_crypt
                    else:
                        self.in_buffer_pos = 0
                else:
                    if self.is_encrypt:
                        if self.in_buffer_pos > 0:
                            tail = bytes(self.in_buffer[0:self.in_buffer_pos])
                            self.in_buffer_pos = 0
                            if not self.is_gcm:
                                tail = pad_data(tail)
                            crypted = self.crypter.update(tail)
                            crypted += self.crypter.finalize()
                            if self.is_gcm:
                                crypted += self.crypter.tag
                    else:
                        if self.in_buffer_pos == 16:
                            if self.is_gcm:
                                tag = bytes(self.in_buffer[0: self.in_buffer_pos])
                                crypted = self.crypter.finalize_with_tag(tag)
                            else:
                                crypted = self.crypter.update(self.in_buffer[0: self.in_buffer_pos]) + self.crypter.finalize()
                                crypted = unpad_data(crypted)
                            self.in_buffer_pos = 0
                if crypted:
                    self.out_buffer[self.out_buffer_pos: self.out_buffer_pos + len(crypted)] = crypted
                    self.out_buffer_pos += len(crypted)

            if self.out_buffer_pos > 0:
                b_len = min(len(buffer) - buffer_len, self.out_buffer_pos)
                mv[buffer_len:buffer_len+b_len] = self.out_buffer[0:b_len]
                if self.out_buffer_pos > b_len:
                    self.out_buffer[0:self.out_buffer_pos - b_len] = self.out_buffer[b_len:self.out_buffer_pos]
                    self.out_buffer_pos -= b_len
                else:
                    self.out_buffer_pos = 0
                buffer_len += b_len
            else:
                break

        return buffer_len


class StreamCrypter(_StreamCrypter):
    __doc__ = _StreamCrypter.__doc__
