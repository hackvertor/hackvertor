package burp;

import java.util.List;

public interface IHttpRequestResponseWithMarkers extends IHttpRequestResponse {
    List<int[]> getRequestMarkers();
    List<int[]> getResponseMarkers();
}