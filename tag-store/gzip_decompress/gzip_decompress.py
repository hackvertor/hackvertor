import base64
import gzip
from io import BytesIO

compressed_data = base64.b64decode(input)

buf = BytesIO(compressed_data)
with gzip.GzipFile(fileobj=buf, mode='rb') as gzip_file:
    decoded_data = gzip_file.read()

output = base64.b64encode(decoded_data).decode('utf-8')