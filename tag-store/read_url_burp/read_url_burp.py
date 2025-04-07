import re
from burp.api.montoya.http.message.requests import HttpRequest

isHttp = r"^https?://"
if re.match(isHttp, input):
   output = str(HackvertorExtension.montoyaApi.http().sendRequest(HttpRequest.httpRequestFromUrl(input)).response().toString())
else:
   output = "Invalid URL"