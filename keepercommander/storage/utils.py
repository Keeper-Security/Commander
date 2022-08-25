#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import base64
import time
import logging

from urllib.parse import urlparse

from .. import crypto


def get_logger(name='keeper-sdk'):   # type: (str) -> logging.Logger
    return logging.getLogger(name)


def generate_uid():   # type: () -> str
    return base64_url_encode(crypto.get_random_bytes(16))


def generate_aes_key():  # type: () -> bytes
    return crypto.get_random_bytes(32)


def current_milli_time():  # type: () -> int
    return int(round(time.time() * 1000))


def base64_url_decode(s):  # type: (str) -> bytes
    return base64.urlsafe_b64decode(s + '==')


def base64_url_encode(b):  # type: (bytes) -> str
    bs = base64.urlsafe_b64encode(b)
    return bs.decode('utf-8').rstrip('=')


def url_strip(url):   # type: (str) -> str
    try:
        result = urlparse(url)
        return result.netloc + result.path
    except Exception:
        return ''


def decrypt_encryption_params(encryption_params, password):  # type: (bytes, str) -> bytes
    if len(encryption_params) != 100:
        raise Exception('Invalid encryption params: bad params length')

    _ = int.from_bytes(encryption_params[0:1], byteorder='big', signed=False)
    iterations = int.from_bytes(encryption_params[1:4], byteorder='big', signed=False)
    salt = encryption_params[4:20]
    encrypted_data_key = encryption_params[20:]

    key = crypto.derive_key_v1(password, salt, iterations)
    decrypted_data_key = crypto.decrypt_aes_v1(encrypted_data_key, key, use_padding=False)

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise Exception('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise Exception('Invalid data key: failed mirror verification')

    return decrypted_data_key[:32]


def create_encryption_params(password, salt, iterations, data_key):  # type: (str, bytes, int, bytes) -> bytes
    key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    enc_iv = crypto.get_random_bytes(16)
    enc_data_key = crypto.encrypt_aes_v1(data_key * 2, key, iv=enc_iv, use_padding=False)
    return b'\x01' + enc_iter + salt + enc_data_key


def create_auth_verifier(password, salt, iterations):  # type: (str, bytes, int) -> bytes
    derived_key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    return b'\x01' + enc_iter + salt + derived_key
