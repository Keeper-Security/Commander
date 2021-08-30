#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import base64
import time

from . import crypto


def generate_uid():             # type: () -> str
    return base64_url_encode(crypto.get_random_bytes(16))


def generate_aes_key():         # type: () -> bytes
    return crypto.get_random_bytes(32)


def current_milli_time():       # type: () -> int
    return int(round(time.time() * 1000))


def base64_url_decode(s):       # type: (str) -> bytes
    return base64.urlsafe_b64decode(s + '==')


def base64_url_encode(b):       # type: (bytes) -> str
    bs = base64.urlsafe_b64encode(b)
    return bs.decode('utf-8').rstrip('=')


def decrypt_encryption_params(encryption_params, password):     # type: (str, str) -> bytes

    decoded_encryption_params = base64_url_decode(encryption_params)
    if len(decoded_encryption_params) != 100:
        raise Exception('Invalid encryption params: bad params length')

    _ = int.from_bytes(decoded_encryption_params[0:1], byteorder='big', signed=False)
    iterations = int.from_bytes(decoded_encryption_params[1:4], byteorder='big', signed=False)
    salt = decoded_encryption_params[4:20]
    encrypted_data_key = decoded_encryption_params[20:]

    key = crypto.derive_key_v1(password, salt, iterations)
    decrypted_data_key = crypto.decrypt_aes_v1(encrypted_data_key, key, use_padding=False)

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise Exception('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise Exception('Invalid data key: failed mirror verification')

    return decrypted_data_key[:32]


def create_encryption_params(password, salt, iterations, data_key):  # type: (str, bytes, int, bytes) -> str

    key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    enc_iv = crypto.get_random_bytes(16)
    enc_data_key = crypto.encrypt_aes_v1(data_key * 2, key, use_padding=False)
    enc_params = b'\x01' + enc_iter + salt + enc_iv + enc_data_key
    return base64_url_encode(enc_params)


def create_auth_verifier(password, salt, iterations):   # type: (str, bytes, int) -> str

    derived_key = crypto.derive_keyhash_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    auth_ver = b'\x01' + enc_iter + salt + derived_key
    return base64_url_encode(auth_ver)


def confirm(msg):
    """Simple confirmation through user input

    msg(str): Message expecting a yes or no answer
    Returns True if answer is "yes" and False otherwise.
    """
    question = f'{msg} (y/n) '
    answer = ''
    while answer not in ('y', 'n'):
        answer = input(question).lower()
    return answer == 'y'
