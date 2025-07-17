package burp;

import java.util.List;

public interface IResponseInfo {
    List<String> getHeaders();
    int getBodyOffset();
    short getStatusCode();
    List<ICookie> getCookies();
    String getStatedMimeType();
    String getInferredMimeType();
}