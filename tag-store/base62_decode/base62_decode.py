charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
base = 62

def _value(ch, charset):
    try:
        return charset.index(ch)
    except ValueError:
        raise ValueError("base62: Invalid character (%s)" % ch)

def decode(encoded):
    l, i, v = len(encoded), 0, 0
    for x in encoded:
        v += _value(x, charset=charset) * (base ** (l - (i + 1)))
        i += 1
    return v

def decodebytes(encoded):

    leading_null_bytes = b""
    while encoded.startswith("0") and len(encoded) >= 2:
        leading_null_bytes += b"\x00" * _value(encoded[1], charset)
        encoded = encoded[2:]
    decoded = decode(encoded)
    buf = bytearray()
    while decoded > 0:
        buf.append(decoded & 0xFF)
        decoded //= 256
    buf.reverse()

    return leading_null_bytes + bytes(buf)

output = decodebytes(input)