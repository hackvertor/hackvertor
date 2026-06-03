package burp;

import burp.hv.Convertors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SmartDecodeEmailBase64Tests extends BaseHackvertorTest {

    private String base64(String text) {
        return hackvertor.convert("<@base64>" + text + "</@base64>", hackvertor);
    }

    private String wrap(String data, int width, String newline) {
        StringBuilder wrapped = new StringBuilder();
        for (int i = 0; i < data.length(); i += width) {
            if (i > 0) {
                wrapped.append(newline);
            }
            wrapped.append(data, i, Math.min(i + width, data.length()));
        }
        return wrapped.toString();
    }

    private String smartDecode(String text) {
        String full = hackvertor.convert("<@auto_decode_no_decrypt>" + text + "</@auto_decode_no_decrypt>", hackvertor);
        return full.equals(text)
                ? hackvertor.convert("<@auto_decode_partial>" + text + "</@auto_decode_partial>", hackvertor)
                : full;
    }

    private int countOccurrences(String haystack, String needle) {
        int count = 0;
        int index = 0;
        while ((index = haystack.indexOf(needle, index)) != -1) {
            count++;
            index += needle.length();
        }
        return count;
    }

    @Test
    void verificationCodeEmailMultilineBase64DecodesAsSingleTag() {
        String body = "PortSwigger\n    Your verification code\n    Your verification code is:\n          597257\n    This code will expire in 5 minutes.\n";
        String wrappedBody = wrap(base64(body), 76, "\n");
        String email = "Content-Type: text/plain; charset=UTF-8\n" +
                "Content-Transfer-Encoding: base64\n\n" +
                wrappedBody;

        String result = smartDecode(email);

        assertEquals(1, countOccurrences(result, "<@base64>"));
        assertEquals(1, countOccurrences(result, "</@base64>"));
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));
    }

    @Test
    void multilineBase64WithCrlfLineEndingsDecodesAsSingleTag() {
        String body = "Hello recipient,\r\nThis message body was base64 encoded and wrapped using CRLF line endings just like a real SMTP message.\r\nRegards,\r\nThe Team\r\n";
        String wrappedBody = wrap(base64(body), 76, "\r\n");
        String email = "Content-Type: text/plain; charset=UTF-8\r\n" +
                "Content-Transfer-Encoding: base64\r\n\r\n" +
                wrappedBody;

        String result = smartDecode(email);

        assertEquals(1, countOccurrences(result, "<@base64>"));
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));
    }

    @Test
    void multilineBase64WithUtf8CharactersDecodesAsSingleTag() {
        String body = "Café menu\nEspresso £2.50\nCroissant © 2026 The Bakery. All rights reserved.\n";
        String wrappedBody = wrap(base64(body), 76, "\n");
        String email = "Subject: Your order\n" +
                "Content-Transfer-Encoding: base64\n\n" +
                wrappedBody;

        String result = smartDecode(email);

        assertEquals(1, countOccurrences(result, "<@base64>"));
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));
    }

    @Test
    void longMultilineBase64BodyWrappedAtSeventySixDecodesAsSingleTag() {
        String body = "The quick brown fox jumps over the lazy dog. ".repeat(20);
        String wrappedBody = wrap(base64(body), 76, "\r\n");
        String email = "Content-Type: text/plain; charset=UTF-8\r\n" +
                "Content-Transfer-Encoding: base64\r\n\r\n" +
                wrappedBody;

        String result = smartDecode(email);

        assertEquals(1, countOccurrences(result, "<@base64>"));
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));
    }

    @Test
    void multipartEmailWithTwoMultilineBase64PartsDecodesBothAsTags() {
        String textPart = "Your verification code is 597257.\nThis code expires in 5 minutes.\n";
        String htmlPart = "<html><body><h1>Your verification code</h1><p>597257</p></body></html>\n";
        String email = "Content-Type: multipart/mixed; boundary=BOUNDARY\n\n" +
                "--BOUNDARY\n" +
                "Content-Type: text/plain; charset=UTF-8\n" +
                "Content-Transfer-Encoding: base64\n\n" +
                wrap(base64(textPart), 76, "\n") + "\n" +
                "--BOUNDARY\n" +
                "Content-Type: text/html; charset=UTF-8\n" +
                "Content-Transfer-Encoding: base64\n\n" +
                wrap(base64(htmlPart), 76, "\n") + "\n" +
                "--BOUNDARY--\n";

        String result = smartDecode(email);

        assertEquals(2, countOccurrences(result, "<@base64>"));
        assertEquals(2, countOccurrences(result, "</@base64>"));
        assertTrue(result.contains("<@base64>" + textPart + "</@base64>"));
        assertTrue(result.contains("<@base64>" + htmlPart + "</@base64>"));
    }

    @Test
    void multilineBase64BodyTagsReproduceOriginalContent() {
        String body = "Reproducible body content that survives a decode then encode round trip.\n";
        String canonical = base64(body);
        String wrappedBody = wrap(canonical, 76, "\n");
        String email = "Content-Transfer-Encoding: base64\n\n" + wrappedBody;

        String result = smartDecode(email);
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));

        String reEncoded = hackvertor.convert("<@base64>" + body + "</@base64>", hackvertor);
        assertEquals(canonical, reEncoded);
        assertEquals(body, hackvertor.convert("<@d_base64>" + reEncoded + "</@d_base64>", hackvertor));
    }

    @Test
    void multilineBase64SurroundedByPlainTextPreservesSurroundingContent() {
        String body = "Decoded body between markers.\n";
        String wrappedBody = wrap(base64(body), 76, "\n");
        String email = "BEGIN_MARKER\n" + wrappedBody + "\nEND_MARKER";

        String result = smartDecode(email);

        assertTrue(result.startsWith("BEGIN_MARKER\n"));
        assertTrue(result.endsWith("\nEND_MARKER"));
        assertTrue(result.contains("<@base64>" + body + "</@base64>"));
    }

    @Test
    void multilineBase64EmailDoesNotThrow() {
        String body = "No exception should ever escape smart decode for this message.\n".repeat(5);
        String wrappedBody = wrap(base64(body), 76, "\r\n");
        String email = "Content-Transfer-Encoding: base64\r\n\r\n" + wrappedBody;

        assertDoesNotThrow(() -> smartDecode(email));
    }
}
