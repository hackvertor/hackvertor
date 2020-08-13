package burp;

import java.util.ArrayList;
import java.util.HashMap;

import static burp.BurpExtender.helpers;

public class HackvertorPayloadProcessor implements IIntruderPayloadProcessor {
    private final Hackvertor hackvertor;
    private final String name;
    private final String tag;

    HackvertorPayloadProcessor(Hackvertor hackvertor, String name, String tag) {
        this.hackvertor = hackvertor;
        this.name = name;
        this.tag = tag;
    }

    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        String input = helpers.bytesToString(currentPayload);
        byte[] output = helpers.stringToBytes(Convertors.callTag(new HashMap<>(), hackvertor.getCustomTags(), this.tag, input, new ArrayList<String>()));
        return output;
    }

    public String getProcessorName() {
        return this.name;
    }
}
