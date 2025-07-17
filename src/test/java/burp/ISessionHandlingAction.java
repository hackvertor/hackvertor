package burp;

public interface ISessionHandlingAction {
    String getActionName();
    void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems);
}