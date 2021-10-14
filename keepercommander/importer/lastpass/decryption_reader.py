from base64 import b64decode
from io import RawIOBase, BufferedReader, TextIOWrapper, IOBase, BytesIO
from os.path import isfile

from Crypto.Cipher import AES


# Chunk size must be a multiple of 256
# Two b64 decodes each requiring a multiple of four times multiple of 16 needed for AES decryption (4 * 16 * 4 = 256)
CHUNK_SIZE = 8 * 1024


def decode_aes256_base64_from_stream(stream, encryption_key, chunk_size=CHUNK_SIZE):
    """Decrypts base64 encoded AES-256 from file in chunks

    CHUNK_SIZE is read in but only 9/16 of CHUNK_SIZE is yielded for every iteration due to b64 decoding
    """
    first_chunk = stream.read(chunk_size)
    if not first_chunk:
        return

    # LastPass AES-256/CBC/base64 encryted string starts with an "!".
    # Next 24 bytes are the base64 encoded IV for the cipher.
    # Then comes the "|".
    # And the rest is the base64 encoded encrypted payload.
    if first_chunk[0] == b'!'[0]:
        iv = b64decode(first_chunk[1:25])
        aes = AES.new(encryption_key, AES.MODE_CBC, iv)
        chunk = b64decode(first_chunk[26:] + stream.read(26))
        if not chunk:
            return
    else:
        aes = AES.new(encryption_key, AES.MODE_ECB)
        chunk = b64decode(first_chunk)

    d = aes.decrypt(chunk)
    chunk = b64decode(stream.read(chunk_size))

    while chunk:
        yield b64decode(d)
        d = aes.decrypt(chunk)
        chunk = b64decode(stream.read(chunk_size))

    yield b64decode(d[:-d[-1]])


class DecryptionReader(RawIOBase):
    """A RawIOBase reader that decrypts and decodes the input stream"""

    def __init__(self, filename_or_stream, key):
        if isinstance(filename_or_stream, IOBase):
            self.encrypted_stream = filename_or_stream
        elif isfile(filename_or_stream):
            self.encrypted_stream = open(filename_or_stream, 'rb')
        else:
            # Fail silently with empty stream
            self.encrypted_stream = BytesIO()

        self.decryption_generator = decode_aes256_base64_from_stream(self.encrypted_stream, key)
        self.leftover = None

    def readable(self):
        return True

    def readinto(self, b):
        try:
            buf_len = len(b)
            chunk = self.leftover or next(self.decryption_generator)
            output = chunk[:buf_len]
            self.leftover = chunk[buf_len:]
            ret_len = len(output)
            b[:ret_len] = output
            return ret_len
        except StopIteration:
            return 0

    def close(self):
        self.encrypted_stream.close()

    @classmethod
    def get_buffered_reader(cls, encrypted_stream, key):
        return BufferedReader(cls(encrypted_stream, key))

    @classmethod
    def get_text_reader(cls, encrypted_stream, key, **kwargs):
        buffered_reader = cls.get_buffered_reader(encrypted_stream, key)
        return TextIOWrapper(buffered_reader, **kwargs)
