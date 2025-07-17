package burp;

public interface IInterceptedProxyMessage extends IHttpRequestResponse {
    int getMessageReference();
    String getListenerInterface();
    IHttpService getHttpService();
    void setHttpService(IHttpService httpService);
    byte[] getRequest();
    void setRequest(byte[] message);
    byte[] getResponse();
    void setResponse(byte[] message);
    String getComment();
    void setComment(String comment);
    String getHighlight();
    void setHighlight(String color);
    int getInterceptAction();
    void setInterceptAction(int action);
}