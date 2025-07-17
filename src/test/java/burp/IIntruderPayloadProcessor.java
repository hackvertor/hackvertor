package burp;

public interface IIntruderPayloadProcessor {
    String getProcessorName();
    byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue);
}