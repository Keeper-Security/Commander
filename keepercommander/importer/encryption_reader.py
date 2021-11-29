import os
from io import RawIOBase, BufferedReader, IOBase, BytesIO

from Cryptodome.Cipher import AES


CHUNK_SIZE = 8 * 1024


def encode_aes_from_stream(stream, encryption_key, aes_mode=AES.MODE_GCM, chunk_size=CHUNK_SIZE):
    """Encrypts using AES from file in chunks"""
    iv = os.urandom(12)
    yield iv
    cipher = AES.new(key=encryption_key, mode=aes_mode, nonce=iv)
    chunk = stream.read(CHUNK_SIZE)
    while chunk:
        yield cipher.encrypt(chunk)
        chunk = stream.read(CHUNK_SIZE)
    yield cipher.digest()


class EncryptionReader(RawIOBase):
    """A RawIOBase reader that encrypts the input stream"""

    def __init__(self, filename_or_stream, key):
        if isinstance(filename_or_stream, IOBase):
            self.stream = filename_or_stream
        elif os.path.isfile(filename_or_stream):
            self.stream = open(filename_or_stream, 'rb')
        else:
            # Fail silently with empty stream
            self.stream = BytesIO()

        self.encryption_generator = encode_aes_from_stream(self.stream, key)
        self.leftover = None

    def readable(self):
        return True

    def readinto(self, b):
        try:
            buf_len = len(b)
            chunk = self.leftover or next(self.encryption_generator)
            output = chunk[:buf_len]
            self.leftover = chunk[buf_len:]
            ret_len = len(output)
            b[:ret_len] = output
            return ret_len
        except StopIteration:
            return 0

    def close(self):
        self.stream.close()

    @classmethod
    def get_buffered_reader(cls, stream, key):
        return BufferedReader(cls(stream, key))
