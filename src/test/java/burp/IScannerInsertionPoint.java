package burp;

public interface IScannerInsertionPoint {
    byte INS_PARAM_URL = 0;
    byte INS_PARAM_BODY = 1;
    byte INS_PARAM_COOKIE = 2;
    byte INS_PARAM_XML = 3;
    byte INS_PARAM_XML_ATTR = 4;
    byte INS_PARAM_MULTIPART_ATTR = 5;
    byte INS_PARAM_JSON = 6;
    byte INS_HEADER = 32;
    byte INS_URL_PATH_FOLDER = 33;
    byte INS_URL_PATH_FILENAME = 34;
    byte INS_URL_PATH_FILENAME_EXT = 35;
    byte INS_URL_QUERY = 36;
    byte INS_URL_FRAGMENT = 37;
    byte INS_EXTENSION_PROVIDED = 64;
    byte INS_UNKNOWN = 127;
    
    String getInsertionPointName();
    String getBaseValue();
    byte[] buildRequest(byte[] payload);
    int[] getPayloadOffsets(byte[] payload);
    byte getInsertionPointType();
}