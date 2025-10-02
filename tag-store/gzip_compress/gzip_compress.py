import base64
import gzip
from io import BytesIO

decoded_data = base64.b64decode(input)

buf = BytesIO()
with gzip.GzipFile(fileobj=buf, mode='wb') as gzip_file:
    gzip_file.write(decoded_data)
compressed_data = buf.getvalue()

output = base64.b64encode(compressed_data).decode('utf-8')