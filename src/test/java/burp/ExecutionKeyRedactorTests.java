package burp;

import burp.hv.utils.ExecutionKeyRedactor;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

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
        // Unique names so the result doesn't depend on global state left by other tests or earlier runs
        String toolA = "TestTool-" + UUID.randomUUID();
        String toolB = "TestTool-" + UUID.randomUUID();
        assertTrue(ExecutionKeyRedactor.shouldLogRedaction(toolA));
        assertFalse(ExecutionKeyRedactor.shouldLogRedaction(toolA));
        assertTrue(ExecutionKeyRedactor.shouldLogRedaction(toolB));
    }

    private static String encodeEachChar(String input, String format) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) sb.append(String.format(format, (int) c));
        return sb.toString();
    }

    private static void assertRedacted(String encodedKey) {
        String input = "q=" + encodedKey + "&x=1";
        assertTrue(ExecutionKeyRedactor.containsKey(input, KEY), encodedKey);
        String redacted = ExecutionKeyRedactor.redact(input, KEY);
        assertFalse(ExecutionKeyRedactor.containsKey(redacted, KEY), redacted);
        assertEquals(input.length(), redacted.length());
        assertTrue(redacted.startsWith("q=") && redacted.endsWith("&x=1"), redacted);
        byte[] redactedBytes = ExecutionKeyRedactor.redact(input.getBytes(StandardCharsets.ISO_8859_1), KEY);
        assertEquals(redacted, new String(redactedBytes, StandardCharsets.ISO_8859_1));
    }

    @Test
    void redactsPercentEncodedKey() {
        assertRedacted(encodeEachChar(KEY, "%%%02x"));
        assertRedacted(encodeEachChar(KEY, "%%%02X"));
        assertRedacted(encodeEachChar(KEY.toUpperCase(), "%%%02X"));
        assertRedacted(encodeEachChar(KEY, "%%25%02x"));
    }

    @Test
    void redactsPartiallyEncodedKey() {
        String partial = KEY.substring(0, 10) + encodeEachChar(KEY.substring(10, 20), "%%%02x") + KEY.substring(20);
        assertRedacted(partial);
    }

    @Test
    void redactsEscapedKey() {
        assertRedacted(encodeEachChar(KEY, "\\u%04x"));
        assertRedacted(encodeEachChar(KEY, "\\x%02x"));
        assertRedacted(encodeEachChar(KEY, "&#%d;"));
        assertRedacted(encodeEachChar(KEY, "&#x%x;"));
    }

    @Test
    void redactsHexEncodedKey() {
        assertRedacted(encodeEachChar(KEY, "%02x"));
        assertRedacted(encodeEachChar(KEY, "%02X"));
    }

    @Test
    void redactsBase64EncodedKeyAtAnyAlignment() {
        for (String prefix : new String[]{"", "a", "ab", "abc"}) {
            byte[] data = (prefix + "<@python('x','" + KEY + "')>").getBytes(StandardCharsets.US_ASCII);
            for (String encoded : new String[]{Base64.getEncoder().encodeToString(data), Base64.getUrlEncoder().encodeToString(data)}) {
                assertTrue(ExecutionKeyRedactor.containsKey(encoded, KEY), encoded);
                String redacted = ExecutionKeyRedactor.redact(encoded, KEY);
                assertEquals(encoded.length(), redacted.length());
                String decoded = new String(Base64.getMimeDecoder().decode(redacted.replace('-', '+').replace('_', '/')), StandardCharsets.ISO_8859_1);
                assertFalse(ExecutionKeyRedactor.containsKey(decoded, KEY), decoded);
            }
        }
    }

    @Test
    void redactsUtf16EncodedKey() {
        for (java.nio.charset.Charset charset : new java.nio.charset.Charset[]{StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE}) {
            byte[] input = ("x=" + KEY).getBytes(charset);
            assertTrue(ExecutionKeyRedactor.containsKey(input, KEY));
            byte[] redacted = ExecutionKeyRedactor.redact(input, KEY);
            assertEquals(input.length, redacted.length);
            assertFalse(ExecutionKeyRedactor.containsKey(new String(redacted, charset), KEY));
        }
    }

    @Test
    void ignoresIncompleteKey() {
        String partialKey = KEY.substring(0, 31);
        assertFalse(ExecutionKeyRedactor.containsKey("a=" + partialKey, KEY));
        assertFalse(ExecutionKeyRedactor.containsKey(encodeEachChar(partialKey, "%%%02x"), KEY));
    }

    @Test
    void scansByteSourceWithoutCopying() {
        byte[] bytes = ("GET /?a=" + KEY + " HTTP/1.1").getBytes(StandardCharsets.US_ASCII);
        ExecutionKeyRedactor.ByteSource source = new ExecutionKeyRedactor.ByteSource() {
            public int length() { return bytes.length; }
            public byte byteAt(int index) { return bytes[index]; }
        };
        assertTrue(ExecutionKeyRedactor.containsKey(source, KEY));
    }
}
