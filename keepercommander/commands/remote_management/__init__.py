from __future__ import annotations
from ...utils import value_to_boolean
import os
import base64
import json
from ...crypto import encrypt_aes_v2, decrypt_aes_v2
from typing import Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from keeper_dag.connection import ConnectionBase


def get_connection(params: KeeperParams) -> ConnectionBase:
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG", False)) is False:
        from keeper_dag.connection.commander import Connection as CommanderConnection
        return CommanderConnection(params=params)
    else:
        from keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection()


# def decrypt(self, cipher_base64: bytes, key: bytes) -> dict:
#     ciphertext = base64.b64decode(cipher_base64)
#     return json.loads(decrypt_aes_v2(ciphertext, key))
#
#
# def encrypt(self, data: dict, key: bytes) -> str:
#     json_data = json.dumps(data)
#     ciphertext = encrypt_aes_v2(json_data.encode(), key)
#     return base64.b64encode(ciphertext).decode()
#
#
# def encrypt_str(self, data: Union[bytes, str], key: bytes) -> str:
#     if isinstance(data, str):
#         data = data.encode()
#     ciphertext = encrypt_aes_v2(data, key)
#     return base64.b64encode(ciphertext).decode()