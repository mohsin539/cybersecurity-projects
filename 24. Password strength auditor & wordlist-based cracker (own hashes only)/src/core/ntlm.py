import struct

_MASK = 0xFFFFFFFF


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK


def _f(x, y, z):
    return (x & y) | (~x & z)


def _g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def _h(x, y, z):
    return x ^ y ^ z


def _md4_digest(data):
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", bytes(msg[off : off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            choice = i % 4
            if choice == 0:
                a = _rotl((a + _f(b, c, d) + x[i]) & _MASK, 3)
            elif choice == 1:
                d = _rotl((d + _f(a, b, c) + x[i]) & _MASK, 7)
            elif choice == 2:
                c = _rotl((c + _f(d, a, b) + x[i]) & _MASK, 11)
            else:
                b = _rotl((b + _f(c, d, a) + x[i]) & _MASK, 19)
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            choice = i % 4
            if choice == 0:
                a = _rotl((a + _g(b, c, d) + x[k] + 0x5A827999) & _MASK, 3)
            elif choice == 1:
                d = _rotl((d + _g(a, b, c) + x[k] + 0x5A827999) & _MASK, 5)
            elif choice == 2:
                c = _rotl((c + _g(d, a, b) + x[k] + 0x5A827999) & _MASK, 9)
            else:
                b = _rotl((b + _g(c, d, a) + x[k] + 0x5A827999) & _MASK, 13)
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            k = order[i]
            choice = i % 4
            if choice == 0:
                a = _rotl((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & _MASK, 3)
            elif choice == 1:
                d = _rotl((d + _h(a, b, c) + x[k] + 0x6ED9EBA1) & _MASK, 9)
            elif choice == 2:
                c = _rotl((c + _h(d, a, b) + x[k] + 0x6ED9EBA1) & _MASK, 11)
            else:
                b = _rotl((b + _h(c, d, a) + x[k] + 0x6ED9EBA1) & _MASK, 15)
        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK
    return struct.pack("<4I", a, b, c, d)


def _try_bcrypt_md4(data):
    try:
        from ..compat.win import bcrypt_md4

        return bcrypt_md4(data)
    except Exception:
        return None


def _md4_bytes(data):
    result = _try_bcrypt_md4(data)
    if result is None:
        result = _md4_digest(data)
    return result


def ntlm_digest(password):
    return _md4_bytes(password.encode("utf-16-le"))


def ntlm_hex(password):
    return ntlm_digest(password).hex()