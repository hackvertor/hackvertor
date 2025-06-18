import zlib

def compress(input):
    return zlib.compress(input.encode('utf-8'))

output = compress(input)