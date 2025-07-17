package burp;

public interface IProxyListener {
    void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message);
}