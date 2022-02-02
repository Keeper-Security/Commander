# implementation of RFC 4648 using optional extended hex alphabet
# https://tools.ietf.org/html/rfc4648#page-10

_b32alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
_b32hexalphabet = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
_b32rev = {}

padChar = "="
padInt = ord(padChar)


def encode(src, str_map):
    dst = []
    src_len = 0

    if len(src) == 0:
        return ''

    while len(src):
        src_len = len(src)
        next_byte = [0] * 8

        if src_len > 4:
            next_byte[7] = src[4] & 0x1f
            next_byte[6] = src[4] >> 5

        if src_len > 3:
            next_byte[6] = next_byte[6] | (src[3] << 3) & 0x1f
            next_byte[5] = (src[3] >> 2) & 0x1f
            next_byte[4] = src[3] >> 7

        if src_len > 2:
            next_byte[4] = next_byte[4] | (src[2] << 1) & 0x1f
            next_byte[3] = (src[2] >> 4) & 0x1f

        if src_len > 1:
            next_byte[3] = next_byte[3] | (src[1] << 4) & 0x1f
            next_byte[2] = (src[1] >> 1) & 0x1f
            next_byte[1] = (src[1] >> 6) & 0x1f

        if src_len > 0:
            next_byte[1] = next_byte[1] | (src[0] << 2) & 0x1f
            next_byte[0] = src[0] >> 3

        for nb in next_byte:
            dst.append(str_map[nb])

        src = src[5:]

    if src_len < 5:
        dst[-1] = padInt
    if src_len < 4:
        dst[-2] = padInt
        dst[-3] = padInt
    if src_len < 3:
        dst[-4] = padInt
    if src_len < 2:
        dst[-5] = padInt
        dst[-6] = padInt

    return ''.join((chr(i) for i in dst))


def decode(src, alphabet):
    global _b32rev
    if alphabet not in _b32rev:
        _b32rev[alphabet] = {chr(v): k for k, v in enumerate(alphabet)}
    b32rev = _b32rev[alphabet]
    src = src.upper()

    end = False
    result = []
    while len(src) > 0 and not end:
        dst = [0] * 5
        dbuf = [0] * 8

        src_len = 8

        for i in range(0, 8):
            if i >= len(src):
                src_len = i
                end = True
                break
            char = src[i]
            if char == padChar:
                end = True
                src_len = i
                break
            else:
                dbuf[i] = b32rev[char]

        if src_len >= 8:
            dst[4] = (dbuf[6] << 5) | (dbuf[7])
        if src_len >= 7:
            dst[3] = (dbuf[4] << 7) | (dbuf[5] << 2) | (dbuf[6] >> 3)
        if src_len >= 5:
            dst[2] = (dbuf[3] << 4) | (dbuf[4] >> 1)
        if src_len >= 4:
            dst[1] = (dbuf[1] << 6) | (dbuf[2] << 1) | (dbuf[3] >> 4)
        if src_len >= 2:
            dst[0] = (dbuf[0] << 3) | (dbuf[1] >> 2)

        dst = list(map(lambda x: x & 0xff, dst))

        if src_len == 2:
            dst = dst[:1]
        elif src_len == 4:
            dst = dst[:2]
        elif src_len == 5:
            dst = dst[:3]
        elif src_len == 7:
            dst = dst[:4]
        elif src_len == 8:
            dst = dst[:5]

        result.extend(dst)
        src = src[8:]

    return result


def _b32encode(src, alphabet):
    if type(src) == str:
        return encode(map(ord, src), alphabet)
    else:
        return encode(src, alphabet)


def b32encode(src):
    return _b32encode(src, _b32alphabet)


def b32hexencode(src):
    return _b32encode(src, _b32hexalphabet)


def b32decode(src):
    return decode(src, _b32alphabet)


def b32hexdecode(src):
    return decode(src, _b32hexalphabet)
