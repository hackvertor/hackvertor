package burp.stubs;

import burp.*;
import java.util.Base64;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class StubExtensionHelpers implements IExtensionHelpers {
    @Override
    public IRequestInfo analyzeRequest(IHttpRequestResponse request) {
        return null;
    }

    @Override
    public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) {
        return null;
    }

    @Override
    public IRequestInfo analyzeRequest(byte[] request) {
        return null;
    }

    @Override
    public IResponseInfo analyzeResponse(byte[] response) {
        return null;
    }

    @Override
    public IParameter getRequestParameter(byte[] request, String parameterName) {
        return null;
    }

    @Override
    public String urlDecode(String data) {
        return null;
    }

    @Override
    public String urlEncode(String data) {
        return null;
    }

    @Override
    public byte[] urlDecode(byte[] data) {
        return new byte[0];
    }

    @Override
    public byte[] urlEncode(byte[] data) {
        return new byte[0];
    }

    @Override
    public byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    @Override
    public byte[] base64Decode(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    @Override
    public String base64Encode(String data) {
        return Base64.getEncoder().encodeToString(data.getBytes());
    }

    @Override
    public String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    @Override
    public byte[] stringToBytes(String data) {
        if (data == null) return new byte[0];
        // In Burp, this returns the raw bytes - treating the string as ISO-8859-1
        return data.getBytes(StandardCharsets.ISO_8859_1);
    }

    @Override
    public String bytesToString(byte[] data) {
        if (data == null) return null;
        // In Burp, this returns a string using ISO-8859-1 encoding to preserve binary data
        return new String(data, StandardCharsets.ISO_8859_1);
    }

    @Override
    public int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
        return 0;
    }

    @Override
    public byte[] buildHttpMessage(List<String> headers, byte[] body) {
        return new byte[0];
    }

    @Override
    public byte[] buildHttpRequest(URL url) {
        return new byte[0];
    }

    @Override
    public byte[] addParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] removeParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] updateParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] toggleRequestMethod(byte[] request) {
        return new byte[0];
    }

    @Override
    public IHttpService buildHttpService(String host, int port, String protocol) {
        return null;
    }

    @Override
    public IHttpService buildHttpService(String host, int port, boolean useHttps) {
        return null;
    }

    @Override
    public IParameter buildParameter(String name, String value, byte type) {
        return null;
    }

    @Override
    public IScannerInsertionPoint makeScannerInsertionPoint(String insertionPointName, byte[] baseRequest, int from, int to) {
        return null;
    }

    @Override
    public IResponseVariations analyzeResponseVariations(byte[]... responses) {
        return null;
    }

    @Override
    public IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses) {
        return null;
    }
}
