package burp.hv.utils;

import java.net.URL;

public class UrlUtils {
    public static String buildUrl(URL url) {
        int port = url.getPort();
        StringBuilder urlResult = new StringBuilder();
        urlResult.append(url.getProtocol());
        urlResult.append(":");
        if (url.getAuthority() != null && !url.getAuthority().isEmpty()) {
            urlResult.append("//");
            urlResult.append(url.getHost());
        }

        if ((url.getProtocol().equals("http") && port != 80) || (url.getProtocol().equals("https") && port != 443) && port != -1) {
            urlResult.append(':').append(port);
        }
        if (url.getPath() != null) {
            urlResult.append(url.getPath());
        }
        if (url.getQuery() != null) {
            urlResult.append("?");
            urlResult.append(url.getQuery());
        }
        if (url.getRef() != null) {
            urlResult.append("#");
            urlResult.append(url.getRef());
        }
        return urlResult.toString();
    }
}
