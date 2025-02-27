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

def generate_api_key():
    """
    Generates a random API key
    """
    raw_key = get_random_bytes(32)
    readable_key = base64.urlsafe_b64encode(raw_key).decode('utf-8')
    return readable_key

