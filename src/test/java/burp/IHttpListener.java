package burp;

public interface IHttpListener {
    void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo);
}