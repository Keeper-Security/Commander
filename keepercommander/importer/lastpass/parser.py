# coding: utf-8
from base64 import b64decode
import binascii
import codecs
from io import BytesIO
import struct
import re
from urllib.parse import urlunsplit, urlencode

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util import number
from Cryptodome.PublicKey import RSA

from .account import Account
from .attachment import LastpassAttachment
from .chunk import Chunk


# Secure note types that contain account-like information
ALLOWED_SECURE_NOTE_TYPES = [
    b"Server",
    b"Email Account",
    b"Database",
    b"Instant Messenger",
]

# TOTP
TOTP_URL_SCHEME = 'otpauth'
TOTP_URL_NETLOC = 'totp'
TOTP_URL_PATH = '/lastpass_import'
TOTP_URL_QUERY_MAPPING = [
    ('algorithm', 'SHA1'),
    ('digits', '6'),
    ('period', '30')
]


def extract_chunks(blob):
    """Splits the blob into chucks grouped by kind."""
    chunks = []
    stream = BytesIO(blob.bytes)
    current_pos = stream.tell()
    stream.seek(0, 2)
    length = stream.tell()
    stream.seek(current_pos, 0)
    while stream.tell() < length:
        chunks.append(read_chunk(stream))

    return chunks


def parse_ACCT(chunk, encryption_key, shared_folder):
    """
    Parses an account chunk, decrypts and creates an Account object.
    May return nil when the chunk does not represent an account.
    All secure notes are ACCTs but not all of them strore account
    information.
    """
    # TODO: Make a test case that covers secure note account

    io = BytesIO(chunk.payload)
    id = read_item(io).decode('utf-8')
    name = decode_aes256_plain_auto(read_item(io), encryption_key)
    group = decode_aes256_plain_auto(read_item(io), encryption_key)
    url = decode_hex(read_item(io))
    notes = decode_aes256_plain_auto(read_item(io), encryption_key)
    skip_item(io, 2)
    username = decode_aes256_plain_auto(read_item(io), encryption_key)
    password = decode_aes256_plain_auto(read_item(io), encryption_key)
    skip_item(io, 2)
    secure_note = read_item(io)
    skip_item(io, 14)

    attach_key_encrypted = read_item(io)
    attach_present = read_item(io)
    if attach_present == b'1' and len(attach_key_encrypted) > 0:
        attach_key = decode_hex(decode_aes256_base64_auto(attach_key_encrypted, encryption_key))
    else:
        attach_key = None

    skip_item(io, 11)
    try:
        totp_secret = decode_aes256_plain_auto(read_item(io), encryption_key).decode('utf-8')
    except Exception:
        totp_secret = None
        totp_url = None
    else:
        if totp_secret:
            totp_query_string = urlencode([('secret', totp_secret)] + TOTP_URL_QUERY_MAPPING)
            totp_url = urlunsplit((TOTP_URL_SCHEME, TOTP_URL_NETLOC, TOTP_URL_PATH, totp_query_string, ''))
        else:
            totp_url = None

    # Parse secure note
    if secure_note == b'1':
        parsed = parse_secure_note_server(notes)

        if parsed.get('type') in ALLOWED_SECURE_NOTE_TYPES:
            url = parsed.get('url', url)
            username = parsed.get('username', username)
            password = parsed.get('password', password)

    return Account(id, name, username, password, url, group, notes, shared_folder, attach_key, totp_secret, totp_url)


def parse_PRIK(chunk, encryption_key):
    """Parse PRIK chunk which contains private RSA key"""
    decrypted = decode_aes256('cbc',
                              encryption_key[:16],
                              decode_hex(chunk.payload),
                              encryption_key)

    hex_key = re.match(br'^LastPassPrivateKey<(?P<hex_key>.*)>LastPassPrivateKey$', decrypted).group('hex_key')
    rsa_key = RSA.importKey(decode_hex(hex_key))

    rsa_key.dmp1 = rsa_key.d % (rsa_key.p - 1)
    rsa_key.dmq1 = rsa_key.d % (rsa_key.q - 1)
    rsa_key.iqmp = number.inverse(rsa_key.q, rsa_key.p)

    return rsa_key


def parse_SHAR(chunk, encryption_key, rsa_key):
    # TODO: Fake some data and make a test
    io = BytesIO(chunk.payload)
    id = read_item(io)
    encrypted_key = decode_hex(read_item(io))
    encrypted_name = read_item(io)
    skip_item(io, 2)
    key = read_item(io)

    # Shared folder encryption key might come already in pre-decrypted form,
    # where it's only AES encrypted with the regular encryption key.
    # When the key is blank, then there's a RSA encrypted key, which has to
    # be decrypted first before use.
    if not key:
        key = decode_hex(PKCS1_OAEP.new(rsa_key).decrypt(encrypted_key))
    else:
        key = decode_hex(decode_aes256_plain_auto(key, encryption_key))

    name = decode_aes256_base64_auto(encrypted_name, key)

    # TODO: Return an object, not a dict
    return {'id': id, 'name': name, 'encryption_key': key}


def parse_ATTA(chunk, accounts):
    attachment = None
    io = BytesIO(chunk.payload)
    id = read_item(io).decode('utf-8')
    parent_id = read_item(io).decode('utf-8')
    mimetype = read_item(io).decode('utf-8')
    storagekey = read_item(io).decode('utf-8')
    lastpass_size = int(read_item(io))
    filename_encrypted = read_item(io)

    parents = [a for a in accounts if a.id == parent_id]
    if len(parents) > 0:
        parent = parents[0]
        if parent.attach_key:
            filename = decode_aes256_base64_auto(filename_encrypted, parent.attach_key).decode('utf-8')
            attachment = LastpassAttachment(id, parent, mimetype, storagekey, lastpass_size, filename)
            parent.attachments.append(attachment)

    return attachment


def parse_secure_note_server(notes):
    info = {}

    for i in notes.split(b'\n'):
        if not i:  # blank line
            continue

        if b':' not in i:  # there is no `:` if generic note
            continue

        # Split only once so that strings like "Hostname:host.example.com:80"
        # get interpreted correctly
        key, value = i.split(b':', 1)
        if key == b'NoteType':
            info['type'] = value
        elif key == b'Hostname':
            info['url'] = value
        elif key == b'Username':
            info['username'] = value
        elif key == b'Password':
            info['password'] = value

    return info


def read_chunk(stream):
    """Reads one chunk from a stream and creates a Chunk object with the data read."""
    # LastPass blob chunk is made up of 4-byte ID,
    # big endian 4-byte size and payload of that size.
    #
    # Example:
    #   0000: "IDID"
    #   0004: 4
    #   0008: 0xDE 0xAD 0xBE 0xEF
    #   000C: --- Next chunk ---
    return Chunk(read_id(stream), read_payload(stream, read_size(stream)))


def read_item(stream):
    """Reads an item from a stream and returns it as a string of bytes."""
    # An item in an itemized chunk is made up of the
    # big endian size and the payload of that size.
    #
    # Example:
    #   0000: 4
    #   0004: 0xDE 0xAD 0xBE 0xEF
    #   0008: --- Next item ---
    return read_payload(stream, read_size(stream))


def skip_item(stream, times=1):
    """Skips an item in a stream."""
    for i in range(times):
        read_item(stream)


def read_id(stream):
    """Reads a chunk ID from a stream."""
    return stream.read(4)


def read_size(stream):
    """Reads a chunk or an item ID."""
    return read_uint32(stream)


def read_payload(stream, size):
    """Reads a payload of a given size from a stream."""
    return stream.read(size)


def read_uint32(stream):
    """Reads an unsigned 32 bit integer from a stream."""
    return struct.unpack('>I', stream.read(4))[0]


def decode_hex(data):
    """Decodes a hex encoded string into raw bytes."""
    try:
        return codecs.decode(data, 'hex_codec')
    except binascii.Error:
        raise TypeError()


def decode_base64(data):
    """Decodes a base64 encoded string into raw bytes."""
    return b64decode(data)


def decode_aes256_plain_auto(data, encryption_key):
    """Guesses AES cipher (EBC or CBD) from the length of the plain data."""
    assert isinstance(data, bytes)
    length = len(data)

    if length == 0:
        return b''
    elif data[0] == b'!'[0] and length % 16 == 1 and length > 32:
        return decode_aes256_cbc_plain(data, encryption_key)
    else:
        return decode_aes256_ecb_plain(data, encryption_key)


def decode_aes256_base64_auto(data, encryption_key):
    """Guesses AES cipher (EBC or CBD) from the length of the base64 encoded data."""
    assert isinstance(data, bytes)
    length = len(data)

    if length == 0:
        return b''
    elif data[0] == b'!'[0]:
        return decode_aes256_cbc_base64(data, encryption_key)
    else:
        return decode_aes256_ecb_base64(data, encryption_key)


def decode_aes256_ecb_plain(data, encryption_key):
    """Decrypts AES-256 ECB bytes."""
    if not data:
        return b''
    else:
        return decode_aes256('ecb', '', data, encryption_key)


def decode_aes256_ecb_base64(data, encryption_key):
    """Decrypts base64 encoded AES-256 ECB bytes."""
    return decode_aes256_ecb_plain(decode_base64(data), encryption_key)


def decode_aes256_cbc_plain(data, encryption_key):
    """Decrypts AES-256 CBC bytes."""
    if not data:
        return b''
    else:
        # LastPass AES-256/CBC encryted string starts with an "!".
        # Next 16 bytes are the IV for the cipher.
        # And the rest is the encrypted payload.
        return decode_aes256('cbc', data[1:17], data[17:], encryption_key)


def decode_aes256_cbc_base64(data, encryption_key):
    """Decrypts base64 encoded AES-256 CBC bytes."""
    if not data:
        return b''
    else:
        # LastPass AES-256/CBC/base64 encryted string starts with an "!".
        # Next 24 bytes are the base64 encoded IV for the cipher.
        # Then comes the "|".
        # And the rest is the base64 encoded encrypted payload.
        return decode_aes256(
            'cbc',
            decode_base64(data[1:25]),
            decode_base64(data[26:]),
            encryption_key)


def decode_aes256(cipher, iv, data, encryption_key):
    """
    Decrypt AES-256 bytes.
    Allowed ciphers are: :ecb, :cbc.
    If for :ecb iv is not used and should be set to "".
    """
    if cipher == 'cbc':
        aes = AES.new(encryption_key, AES.MODE_CBC, iv)
    elif cipher == 'ecb':
        aes = AES.new(encryption_key, AES.MODE_ECB)
    else:
        raise ValueError('Unknown AES mode')
    d = aes.decrypt(data)
    # http://passingcuriosity.com/2009/aes-encryption-in-python-with-m2crypto/
    unpad = lambda s: s[0:-ord(d[-1:])]
    return unpad(d)
