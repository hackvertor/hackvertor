package burp;

import java.net.URL;
import java.util.List;

public interface IExtensionHelpers {
    IRequestInfo analyzeRequest(IHttpRequestResponse request);
    IRequestInfo analyzeRequest(IHttpService httpService, byte[] request);
    IRequestInfo analyzeRequest(byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    IParameter getRequestParameter(byte[] request, String parameterName);
    String urlDecode(String data);
    String urlEncode(String data);
    byte[] urlDecode(byte[] data);
    byte[] urlEncode(byte[] data);
    byte[] base64Decode(String data);
    byte[] base64Decode(byte[] data);
    String base64Encode(String data);
    String base64Encode(byte[] data);
    byte[] stringToBytes(String data);
    String bytesToString(byte[] data);
    int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to);
    byte[] buildHttpMessage(List<String> headers, byte[] body);
    byte[] buildHttpRequest(URL url);
    byte[] addParameter(byte[] request, IParameter parameter);
    byte[] removeParameter(byte[] request, IParameter parameter);
    byte[] updateParameter(byte[] request, IParameter parameter);
    byte[] toggleRequestMethod(byte[] request);
    IHttpService buildHttpService(String host, int port, String protocol);
    IHttpService buildHttpService(String host, int port, boolean useHttps);
    IParameter buildParameter(String name, String value, byte type);
    IScannerInsertionPoint makeScannerInsertionPoint(String insertionPointName, byte[] baseRequest, int from, int to);
    IResponseVariations analyzeResponseVariations(byte[]... responses);
    IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses);
}