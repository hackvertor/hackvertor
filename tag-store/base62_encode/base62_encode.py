charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
base = 62

def _value(ch, charset):
    try:
            return charset.index(ch)
    except ValueError:
            raise ValueError("base62: Invalid character (%s)" % ch)

def b62_encode(n):
    chs = []
    while n > 0:
            n, r = divmod(n, base)
            chs.insert(0, charset[r])
    if not chs:
            return "0"
    return "".join(chs)

def encodebytes(barray):
    barray = bytes(barray)
    leading_zeros_count = 0
    for i in range(len(barray)):
            if barray[i] != 0:
                    break
            leading_zeros_count += 1
    n, r = divmod(leading_zeros_count, len(charset) - 1)
    zero_padding = "0{}".format(charset[-1]) * n
    if r:
            zero_padding += "0{}".format(charset[r])
    if leading_zeros_count == len(barray):
            return zero_padding
    value = b62_encode(int(barray.encode('hex'), 16))
    return zero_padding + value

output = encodebytes(input)