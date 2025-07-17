package burp;

public interface IHttpRequestResponsePersisted extends IHttpRequestResponse {
    void deleteTempFiles();
}