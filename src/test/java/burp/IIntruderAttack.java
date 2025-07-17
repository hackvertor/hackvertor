package burp;

public interface IIntruderAttack {
    IHttpService getHttpService();
    byte[] getRequestTemplate();
}