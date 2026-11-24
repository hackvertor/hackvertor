package burp.hv.utils;

import burp.hv.HackvertorExtension;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Prevents the tag execution key from leaving Burp. If tags fail to convert (e.g. because Burp Scanner
 * mutated them) the raw tag, including the execution key, would otherwise be sent to the target.
 * Matching is case-insensitive. The replacement has the same length as the key so that body lengths
 * (and Content-Length headers) remain valid, and binary data is redacted in place without re-encoding.
 */
public class ExecutionKeyRedactor {
    public static final String REDACTED = "REDACTEDREDACTEDREDACTEDREDACTED";
    private static final Set<String> loggedSources = ConcurrentHashMap.newKeySet();

    /**
     * Returns true only the first time a redaction is reported for the given source (e.g. a Burp tool),
     * so scans that produce many redactions don't flood the log.
     */
    public static boolean shouldLogRedaction(String source) {
        return loggedSources.add(source);
    }

    public static boolean containsKey(String input) {
        return containsKey(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static boolean containsKey(byte[] input) {
        return containsKey(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static String redact(String input) {
        return redact(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static byte[] redact(byte[] input) {
        return redact(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static boolean containsKey(String input, String key) {
        if (input == null || key == null || key.isEmpty()) return false;
        return keyPattern(key).matcher(input).find();
    }

    public static boolean containsKey(byte[] input, String key) {
        if (input == null || key == null || key.isEmpty()) return false;
        return indexOfIgnoreCase(input, key.getBytes(StandardCharsets.US_ASCII), 0) != -1;
    }

    public static String redact(String input, String key) {
        if (!containsKey(input, key)) return input;
        String replacement = new String(replacementFor(key.length()), StandardCharsets.US_ASCII);
        return keyPattern(key).matcher(input).replaceAll(Matcher.quoteReplacement(replacement));
    }

    public static byte[] redact(byte[] input, String key) {
        if (!containsKey(input, key)) return input;
        byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
        byte[] replacement = replacementFor(keyBytes.length);
        byte[] output = input.clone();
        int pos = 0;
        while ((pos = indexOfIgnoreCase(output, keyBytes, pos)) != -1) {
            System.arraycopy(replacement, 0, output, pos, keyBytes.length);
            pos += keyBytes.length;
        }
        return output;
    }

    private static Pattern keyPattern(String key) {
        return Pattern.compile(Pattern.quote(key), Pattern.CASE_INSENSITIVE);
    }

    private static byte[] replacementFor(int length) {
        StringBuilder sb = new StringBuilder(length);
        while (sb.length() < length) {
            sb.append(REDACTED);
        }
        return sb.substring(0, length).getBytes(StandardCharsets.US_ASCII);
    }

    private static int indexOfIgnoreCase(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (toLowerAscii(haystack[i + j]) != toLowerAscii(needle[j])) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static byte toLowerAscii(byte b) {
        return (b >= 'A' && b <= 'Z') ? (byte) (b + 32) : b;
    }
}
