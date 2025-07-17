package burp;

public interface IParameter {
    byte PARAM_URL = 0;
    byte PARAM_BODY = 1;
    byte PARAM_COOKIE = 2;
    byte PARAM_XML = 3;
    byte PARAM_XML_ATTR = 4;
    byte PARAM_MULTIPART_ATTR = 5;
    byte PARAM_JSON = 6;
    
    byte getType();
    String getName();
    String getValue();
    int getNameStart();
    int getNameEnd();
    int getValueStart();
    int getValueEnd();
}