package burp;

public interface IHttpRequestResponse {
    byte[] getRequest();
    void setRequest(byte[] message);
    byte[] getResponse();
    void setResponse(byte[] message);
    String getComment();
    void setComment(String comment);
    String getHighlight();
    void setHighlight(String color);
    IHttpService getHttpService();
    void setHttpService(IHttpService httpService);
}