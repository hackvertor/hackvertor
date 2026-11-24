package burp.hv;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HackvertorHttpHandlerTests {
    @Test
    void headersEndFindsCrlfSeparator() {
        String request = "POST / HTTP/1.1\r\nHost: é.example\r\n\r\nbody";
        assertEquals(request.indexOf("body"), HackvertorHttpHandler.headersEnd(request));
    }

    @Test
    void headersEndFindsLfSeparator() {
        String request = "POST / HTTP/1.1\nHost: example\n\nbody";
        assertEquals(request.indexOf("body"), HackvertorHttpHandler.headersEnd(request));
    }

    @Test
    void headersEndWithoutBodyIsWholeRequest() {
        String request = "GET / HTTP/1.1\r\nHost: example";
        assertEquals(request.length(), HackvertorHttpHandler.headersEnd(request));
    }
}
