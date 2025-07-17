package burp;

import java.util.Date;

public interface ICookie {
    String getDomain();
    String getPath();
    Date getExpiration();
    String getName();
    String getValue();
    boolean isSecure();
    boolean isHttpOnly();
}