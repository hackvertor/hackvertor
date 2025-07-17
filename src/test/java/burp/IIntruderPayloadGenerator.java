package burp;

public interface IIntruderPayloadGenerator {
    boolean hasMorePayloads();
    byte[] getNextPayload(byte[] baseValue);
    void reset();
}