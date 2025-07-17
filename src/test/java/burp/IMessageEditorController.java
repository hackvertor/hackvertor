package burp;

public interface IMessageEditorController {
    IHttpService getHttpService();
    byte[] getRequest();
    byte[] getResponse();
}