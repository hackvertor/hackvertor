package burp.hv.utils;

import burp.IParameter;
import burp.IRequestInfo;
import burp.hv.HackvertorExtension;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class HttpUtils {
    public static int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = HackvertorExtension.helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    public static byte[] fixContentLength(byte[] request) {
        IRequestInfo analyzedRequest = HackvertorExtension.helpers.analyzeRequest(request);
        if (countMatches(request, HackvertorExtension.helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = analyzedRequest.getBodyOffset();
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        } else {
            return request;
        }
    }

    public static int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end && request[i++] != '\n') {
        }
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ':') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 1);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = HackvertorExtension.helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    public static byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(HackvertorExtension.helpers.stringToBytes(" " + value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            throw new RuntimeException("Can't find the header");
        }
    }
}
