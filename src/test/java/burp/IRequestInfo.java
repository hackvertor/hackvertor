package burp;

import java.net.URL;
import java.util.List;

public interface IRequestInfo {
    byte getMethod();
    URL getUrl();
    List<String> getHeaders();
    List<IParameter> getParameters();
    int getBodyOffset();
    byte getContentType();
}