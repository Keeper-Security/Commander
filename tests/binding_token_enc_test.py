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
import hashlib
import os

import keepercommander
from keepercommander.rest_api import encrypt_aes

secret_key = os.urandom(32)
# print("secretKey=%s" % secretKey)

encrypted_data = encrypt_aes(b"ABC", secret_key)
# print("encryptedKey=%s" % encryptedKey)

# hashlib.sha256().update(secret_key).digest()
# binding_token = hashlib.sha256(secret_key).digest()



# h = hashlib.sha256()
# h.update(secret_key)
# binding_token = h.digest()


decrypted_key = keepercommander.rest_api.decrypt_aes(encrypted_data, secret_key)

print(decrypted_key)
