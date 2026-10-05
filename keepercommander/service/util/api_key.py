#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ...crypto import get_random_bytes
import base64
import os

def generate_api_key():
    """
    Generates a random API key
    """
    raw_key = get_random_bytes(32)
    readable_key = base64.urlsafe_b64encode(raw_key).decode('utf-8')
    return readable_key


def read_api_key_from_environment():
    key_file = os.environ.get('KEEPER_SERVICE_API_KEY_FILE')
    if not key_file:
        return None
    with open(key_file) as f:
        api_key = f.read().strip()
    if not api_key:
        raise ValueError(f'API key file {key_file} is empty')
    return api_key
