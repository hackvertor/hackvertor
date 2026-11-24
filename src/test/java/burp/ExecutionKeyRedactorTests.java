package burp;

import burp.hv.utils.ExecutionKeyRedactor;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class ExecutionKeyRedactorTests {
    private static final String KEY = "0123456789abcdef0123456789abcdef";

    @Test
    void detectsKeyInString() {
        assertTrue(ExecutionKeyRedactor.containsKey("GET /?x=%3C@python('code','" + KEY + "')> HTTP/1.1", KEY));
        assertFalse(ExecutionKeyRedactor.containsKey("GET / HTTP/1.1", KEY));
    }

    @Test
    void detectionIgnoresCase() {
        assertTrue(ExecutionKeyRedactor.containsKey(KEY.toUpperCase(), KEY));
        assertTrue(ExecutionKeyRedactor.containsKey(KEY.toUpperCase().getBytes(StandardCharsets.US_ASCII), KEY));
    }

    @Test
    void redactsEveryOccurrenceIgnoringCaseAndPreservesLength() {
        String mixedCase = "0123456789ABCdef0123456789abcDEF";
        String input = "a=" + KEY + "&b=" + mixedCase + "&c=" + KEY;
        String redacted = ExecutionKeyRedactor.redact(input, KEY);
        assertFalse(ExecutionKeyRedactor.containsKey(redacted, KEY));
        assertEquals(input.length(), redacted.length());
        assertEquals("a=" + ExecutionKeyRedactor.REDACTED + "&b=" + ExecutionKeyRedactor.REDACTED + "&c=" + ExecutionKeyRedactor.REDACTED, redacted);
    }

    @Test
    void redactsBytesWithoutTouchingBinaryData() {
        byte[] prefix = {(byte) 0xff, (byte) 0xfe, 0x00, (byte) 0x80};
        byte[] keyBytes = KEY.toUpperCase().getBytes(StandardCharsets.US_ASCII);
        byte[] input = new byte[prefix.length + keyBytes.length + prefix.length];
        System.arraycopy(prefix, 0, input, 0, prefix.length);
        System.arraycopy(keyBytes, 0, input, prefix.length, keyBytes.length);
        System.arraycopy(prefix, 0, input, prefix.length + keyBytes.length, prefix.length);

        byte[] redacted = ExecutionKeyRedactor.redact(input, KEY);
        assertEquals(input.length, redacted.length);
        assertFalse(ExecutionKeyRedactor.containsKey(redacted, KEY));
        for (int i = 0; i < prefix.length; i++) {
            assertEquals(prefix[i], redacted[i]);
            assertEquals(prefix[i], redacted[prefix.length + keyBytes.length + i]);
        }
        assertEquals(ExecutionKeyRedactor.REDACTED, new String(redacted, prefix.length, keyBytes.length, StandardCharsets.US_ASCII));
    }

    @Test
    void leavesInputWithoutKeyUnchanged() {
        String input = "no key here";
        assertSame(input, ExecutionKeyRedactor.redact(input, KEY));
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        assertSame(bytes, ExecutionKeyRedactor.redact(bytes, KEY));
    }

    @Test
    void handlesNullAndMissingKey() {
        assertFalse(ExecutionKeyRedactor.containsKey("anything", (String) null));
        assertFalse(ExecutionKeyRedactor.containsKey((String) null, KEY));
        assertEquals("anything", ExecutionKeyRedactor.redact("anything", (String) null));
        assertNull(ExecutionKeyRedactor.redact((String) null, KEY));
    }

    @Test
    void logsRedactionOncePerSource() {
        assertTrue(ExecutionKeyRedactor.shouldLogRedaction("TestToolA"));
        assertFalse(ExecutionKeyRedactor.shouldLogRedaction("TestToolA"));
        assertTrue(ExecutionKeyRedactor.shouldLogRedaction("TestToolB"));
    }
}
