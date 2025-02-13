package burp.stubs;

import burp.*;
import org.python.apache.xerces.impl.dv.util.Base64;

import java.net.URL;
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
        return new byte[0];
    }

    @Override
    public byte[] base64Decode(byte[] data) {
        return base64Decode(data);
    }

    @Override
    public String base64Encode(String data) {
        return Base64.encode(data.getBytes());
    }

    @Override
    public String base64Encode(byte[] data) {
        return null;
    }

    @Override
    public byte[] stringToBytes(String data) {
        return new byte[0];
    }

    @Override
    public String bytesToString(byte[] data) {
        return null;
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
