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
import base64


SUBST_BYTES = bytearray.fromhex(
    'c3bdb0befff7820a303c50bc4ce26e5feed0cc5c87e0221ba5acd79586f32136'
    '242b903f857d750474f242c04738cd4db862b72c51594606c85d266c541d6bdd'
    '800578f57a551140c29c07182ec5f8baebb544eae1a628ce8b9b14a1a2153e9f'
    'd139106aa90e660daef9996477ed76134e297c93efaf1a614835e9f18dc158d9'
    '431297f6896d57096f7f2ab93479731ede9683c6d5cb27fb682fec7e02d470bb'
    'a441e5d8b6db03b1e3fec4845ba7df69e8168ef0539a5a9e2d1c4fa3637baa92'
    '983d910194cf605617bf08880067da49255efc0c8a20abad9d653b37b48c0f8f'
    'ca0be4d24bfa31b381e719a03a23f44a7172a8c952dcb2fd45e61f33d3c7d632'
)
REVERSE_SUBST_BYTES = bytearray(256)
for i in range(256):
    REVERSE_SUBST_BYTES[SUBST_BYTES[i]] = i


def file_id_to_int64(file_id: str) -> int:
    file_id_bytes = base64.urlsafe_b64decode(file_id + '==')
    if len(file_id_bytes) != 8:
        raise ValueError(f'invalid file id string: {file_id}')
    else:
        return unmask(file_id_bytes)


def unmask(file_id_bytes: bytes) -> int:
    output = 0
    for i in range(7, 0, -1):
        result_piece = REVERSE_SUBST_BYTES[file_id_bytes[i]] ^ file_id_bytes[i-1]
        output |= result_piece << (i * 8)
    return output | REVERSE_SUBST_BYTES[file_id_bytes[0]]
