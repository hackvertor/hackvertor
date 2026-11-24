package burp.hv.utils;

import burp.api.montoya.core.ByteArray;
import burp.hv.HackvertorExtension;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Prevents the tag execution key from leaving Burp. If tags fail to convert (e.g. because Burp Scanner
 * mutated them) or aren't converted at all (e.g. tags are disabled for the tool) the raw tag, including the
 * execution key, would otherwise be sent to the target.
 * <p>
 * The key is matched case-insensitively and in common encoded forms: each character may independently be
 * percent-encoded (once or twice), backslash-x or backslash-u escaped, or an HTML character reference, and the
 * whole key may be hex, base64 (standard or URL-safe, at any alignment) or UTF-16 encoded.
 * <p>
 * Every match is replaced with a placeholder of the same length, so body lengths (and Content-Length headers)
 * remain valid. Byte data is scanned through a Latin-1 view so binary content is never copied or re-encoded.
 * The scan is a single linear pass because it runs on every outgoing request.
 */
public class ExecutionKeyRedactor {
    public static final String REDACTED = "REDACTEDREDACTEDREDACTEDREDACTED";
    private static final Set<String> loggedSources = ConcurrentHashMap.newKeySet();
    private static volatile KeyMatcher cached;

    /** Random access to bytes without copying them, e.g. backed by a byte[] or a Montoya ByteArray. */
    public interface ByteSource {
        int length();
        byte byteAt(int index);

        static ByteSource of(ByteArray bytes) {
            return new ByteSource() {
                public int length() { return bytes.length(); }
                public byte byteAt(int index) { return bytes.getByte(index); }
            };
        }

        static ByteSource of(byte[] bytes) {
            return new ByteSource() {
                public int length() { return bytes.length; }
                public byte byteAt(int index) { return bytes[index]; }
            };
        }
    }

    /**
     * Returns true only the first time a redaction is reported for the given source (e.g. a Burp tool),
     * so scans that produce many redactions don't flood the log.
     */
    public static boolean shouldLogRedaction(String source) {
        return loggedSources.add(source);
    }

    public static boolean containsKey(CharSequence input) {
        return containsKey(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static boolean containsKey(byte[] input) {
        return containsKey(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static boolean containsKey(ByteSource input) {
        return containsKey(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static String redact(String input) {
        return redact(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static byte[] redact(byte[] input) {
        return redact(input, HackvertorExtension.tagCodeExecutionKey);
    }

    public static boolean containsKey(CharSequence input, String key) {
        KeyMatcher matcher = matcherFor(key);
        return input != null && matcher != null && matcher.find(input, 0) != -1;
    }

    public static boolean containsKey(byte[] input, String key) {
        return input != null && containsKey(ByteSource.of(input), key);
    }

    public static boolean containsKey(ByteSource input, String key) {
        return input != null && containsKey(latin1(input), key);
    }

    public static String redact(String input, String key) {
        KeyMatcher matcher = matcherFor(key);
        if (input == null || matcher == null) return input;
        long match = matcher.find(input, 0);
        if (match == -1) return input;
        StringBuilder sb = new StringBuilder(input);
        while (match != -1) {
            int start = (int) (match >>> 32), end = (int) match;
            sb.replace(start, end, placeholder(end - start));
            match = matcher.find(input, end);
        }
        return sb.toString();
    }

    public static byte[] redact(byte[] input, String key) {
        KeyMatcher matcher = matcherFor(key);
        if (input == null || matcher == null) return input;
        CharSequence chars = latin1(ByteSource.of(input));
        long match = matcher.find(chars, 0);
        if (match == -1) return input;
        byte[] output = input.clone();
        while (match != -1) {
            int start = (int) (match >>> 32), end = (int) match;
            byte[] replacement = placeholder(end - start).getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(replacement, 0, output, start, replacement.length);
            match = matcher.find(chars, end);
        }
        return output;
    }

    private static String placeholder(int length) {
        StringBuilder sb = new StringBuilder(length);
        while (sb.length() < length) {
            sb.append(REDACTED);
        }
        return sb.substring(0, length);
    }

    private static CharSequence latin1(ByteSource source) {
        return latin1(source, 0, source.length());
    }

    private static CharSequence latin1(ByteSource source, int start, int end) {
        return new CharSequence() {
            public int length() { return end - start; }
            public char charAt(int index) { return (char) (source.byteAt(start + index) & 0xff); }
            public CharSequence subSequence(int s, int e) { return latin1(source, start + s, start + e); }
            public String toString() {
                StringBuilder sb = new StringBuilder(length());
                for (int i = 0; i < length(); i++) sb.append(charAt(i));
                return sb.toString();
            }
        };
    }

    private static KeyMatcher matcherFor(String key) {
        if (key == null || key.isEmpty()) return null;
        KeyMatcher current = cached;
        if (current != null && current.key.equals(key)) return current;
        current = new KeyMatcher(key);
        cached = current;
        return current;
    }

    private static final class KeyMatcher {
        final String key;
        final char[] keyLower;
        // Whole-key encodings (hex, UTF-16, base64) indexed by their first character
        final char[][][] literalsByFirstChar = new char[256][][];

        KeyMatcher(String key) {
            this.key = key;
            this.keyLower = key.toLowerCase(Locale.ROOT).toCharArray();
            Set<String> literals = new LinkedHashSet<>();
            for (String variant : new String[]{key.toLowerCase(Locale.ROOT), key.toUpperCase(Locale.ROOT)}) {
                byte[] bytes = variant.getBytes(StandardCharsets.ISO_8859_1);
                literals.add(toHex(bytes));
                literals.add(toHex(bytes).toUpperCase(Locale.ROOT));
                literals.add(new String(variant.getBytes(StandardCharsets.UTF_16LE), StandardCharsets.ISO_8859_1));
                literals.add(new String(variant.getBytes(StandardCharsets.UTF_16BE), StandardCharsets.ISO_8859_1));
                for (String core : base64Cores(bytes)) {
                    literals.add(core);
                    literals.add(core.replace('+', '-').replace('/', '_'));
                }
            }
            List<List<char[]>> buckets = new ArrayList<>();
            for (int i = 0; i < 256; i++) buckets.add(null);
            for (String literal : literals) {
                char first = literal.charAt(0);
                if (buckets.get(first) == null) buckets.set(first, new ArrayList<>());
                buckets.get(first).add(literal.toCharArray());
            }
            for (int i = 0; i < 256; i++) {
                if (buckets.get(i) != null) literalsByFirstChar[i] = buckets.get(i).toArray(new char[0][]);
            }
        }

        /** Returns (start << 32 | end) of the first match at or after from, or -1. */
        long find(CharSequence s, int from) {
            int n = s.length();
            char firstKeyChar = keyLower[0];
            for (int i = from; i < n; i++) {
                char c = s.charAt(i);
                if (c == '%' || c == '\\' || c == '&' || toLowerAscii(c) == firstKeyChar) {
                    int end = matchEncoded(s, i, n);
                    if (end != -1) return ((long) i << 32) | end;
                }
                if (c < 256) {
                    char[][] candidates = literalsByFirstChar[c];
                    if (candidates != null) {
                        for (char[] literal : candidates) {
                            if (regionMatches(s, i, n, literal)) return ((long) i << 32) | (i + literal.length);
                        }
                    }
                }
            }
            return -1;
        }

        /** Matches the key where every character may be literal (any case) or individually encoded. */
        private int matchEncoded(CharSequence s, int pos, int n) {
            int p = pos;
            for (char expected : keyLower) {
                if (p >= n) return -1;
                long token = decodeToken(s, p, n);
                if (toLowerAscii((char) (token & 0xffff)) == expected) {
                    p += (int) (token >>> 16);
                } else if (toLowerAscii(s.charAt(p)) == expected) {
                    p++;
                } else {
                    return -1;
                }
            }
            return p;
        }

        private static boolean regionMatches(CharSequence s, int pos, int n, char[] literal) {
            if (pos + literal.length > n) return false;
            for (int j = 0; j < literal.length; j++) {
                if (s.charAt(pos + j) != literal[j]) return false;
            }
            return true;
        }
    }

    /** Decodes one possibly-encoded character at p. Returns (length << 16 | decoded char). */
    private static long decodeToken(CharSequence s, int p, int n) {
        char c = s.charAt(p);
        if (c == '%') {
            if (p + 4 < n && s.charAt(p + 1) == '2' && s.charAt(p + 2) == '5') {
                int v = hexPair(s, p + 3);
                if (v >= 0) return token(5, v);
            }
            if (p + 2 < n) {
                int v = hexPair(s, p + 1);
                if (v >= 0) return token(3, v);
            }
        } else if (c == '\\' && p + 1 < n) {
            char type = s.charAt(p + 1);
            if ((type == 'x' || type == 'X') && p + 3 < n) {
                int v = hexPair(s, p + 2);
                if (v >= 0) return token(4, v);
            }
            if ((type == 'u' || type == 'U') && p + 5 < n && s.charAt(p + 2) == '0' && s.charAt(p + 3) == '0') {
                int v = hexPair(s, p + 4);
                if (v >= 0) return token(6, v);
            }
        } else if (c == '&' && p + 2 < n && s.charAt(p + 1) == '#') {
            int q = p + 2;
            boolean hex = s.charAt(q) == 'x' || s.charAt(q) == 'X';
            if (hex) q++;
            int value = 0, digits = 0;
            while (q < n && digits < 8) {
                int d = hex ? hexValue(s.charAt(q)) : decimalValue(s.charAt(q));
                if (d < 0) break;
                value = value * (hex ? 16 : 10) + d;
                q++;
                digits++;
            }
            if (digits > 0 && value < 0x10000) {
                if (q < n && s.charAt(q) == ';') q++;
                return token(q - p, value);
            }
        }
        return token(1, c);
    }

    private static long token(int length, int value) {
        return ((long) length << 16) | value;
    }

    private static int hexPair(CharSequence s, int p) {
        int hi = hexValue(s.charAt(p)), lo = hexValue(s.charAt(p + 1));
        return hi < 0 || lo < 0 ? -1 : (hi << 4) | lo;
    }

    private static int hexValue(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static int decimalValue(char c) {
        return c >= '0' && c <= '9' ? c - '0' : -1;
    }

    private static char toLowerAscii(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
    }

    private static List<String> base64Cores(byte[] bytes) {
        List<String> cores = new ArrayList<>();
        for (int offset = 0; offset < 3; offset++) {
            byte[] padded = new byte[offset + bytes.length];
            System.arraycopy(bytes, 0, padded, offset, bytes.length);
            String encoded = Base64.getEncoder().withoutPadding().encodeToString(padded);
            int start = (8 * offset + 5) / 6;
            int end = (8 * (offset + bytes.length)) / 6;
            cores.add(encoded.substring(start, end));
        }
        return cores;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
