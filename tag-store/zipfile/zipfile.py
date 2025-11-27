# Pentagrid AG, pentagridsec

# Work around the problem that zipfile is the name of the standard library but also this file
# Attention: Cursed Python ahead.
import sys
local = sys.path.pop(0)
import zipfile as zipfileLibrary
sys.path.insert(0, local)


import time

# argument 1, filename, default "test.png"
try:
    filename_from_argument = filename
except NameError:
    filename_from_argument = "test.txt"
# argument 2, isBase64, default 0
try:
    is_base64_encoded = isBase64
except NameError:
    is_base64_encoded = 0
# input (between tags), default empty string
file_content = input
# input is actually a built-in function of Python, so it's always defined...
if callable(file_content):
    file_content = "This is the test file content"

file_content = file_content.encode("utf-8")

if is_base64_encoded:
    file_content = file_content.decode("base64")


# Create zip file, using in-memory memory_buffer
# memory_buffer = StringIO.StringIO()
# As the above leads to unicode errors, try something else
JYTHON=False
PYTHON3=False
PYTHON2=False
try:
    # Jython: use Java byte array output stream
    from java.io import ByteArrayOutputStream
    class MemoryBuffer(object):
        def __init__(self):
            self._buf = ByteArrayOutputStream()
            self._pos = 0

        def write(self, b):
            if isinstance(b, unicode):
                b = b.encode('utf-8')
            if isinstance(b, bytearray):
                b = bytes(b)
            self._buf.write(b)   # always calls write(byte[])
            self._pos = len(self._buf.toByteArray())

        def tell(self):
            return self._pos

        def seek(self, offset, whence=0):
            # We don't support random-access writes, but ZipFile only uses seek(0)
            if whence == 0 and offset == 0:
                self._pos = 0
            else:
                # Not required for writing ZIPs
                pass

        def getvalue(self):
            return self._buf.toByteArray()

        # ZipFile checks for "read" in some cases; safe to implement
        def read(self, n=-1):
            data = self._buf.toByteArray()
            if n == -1:
                return data
            return data[:n]
        
        def flush(self):
            pass
        
    memory_buffer = MemoryBuffer()
    JYTHON=True
except ImportError:
    # CPython / Python 3
    try:
        # Python 3
        import io
        memory_buffer = io.BytesIO()
        PYTHON3=True
    except ImportError:
        # Python 2.7
        import cStringIO
        memory_buffer = cStringIO.StringIO
        PYTHON2=True


zf = zipfileLibrary.ZipFile(memory_buffer, mode='w', compression=zipfileLibrary.ZIP_DEFLATED)

# Create empty directories if the file should be in directories
if '/' in filename_from_argument:
    splitted = filename_from_argument.split("/")
    directories = splitted[:-1]
    parents = ""
    for directory in directories:
        dir_info = zipfileLibrary.ZipInfo(parents + directory + "/")
        parents += directory + "/"
        dir_info.date_time = time.localtime(time.time())[:6]
        dir_info.external_attr = 0o755 << 16
        zf.writestr(dir_info, '')

# Put file in zip file
info = zipfileLibrary.ZipInfo(filename_from_argument)
info.date_time = time.localtime(time.time())[:6]
info.external_attr = 0o777 << 16
zf.writestr(info, file_content)

zf.close()


if JYTHON:
    output = ''.join(map(lambda x: chr(x % 256), memory_buffer.getvalue()))
else:
    output = memory_buffer.getvalue()

print(repr(output))