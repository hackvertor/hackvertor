package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class GzipDebugTest extends BaseHackvertorTest {
    
    @Test
    void testSimpleGzipCompress() {
        String input = "test";
        String compressed = hackvertor.convert("<@gzip_compress>" + input + "</@gzip_compress>", hackvertor);
        assertNotNull(compressed, "Compression should not return null");
        assertFalse(compressed.startsWith("Error:"), "Should not have error: " + compressed);
    }
    
    @Test
    void testGzipRoundTrip() {
        String input = "Hello World!";
        String compressed = hackvertor.convert("<@gzip_compress>" + input + "</@gzip_compress>", hackvertor);
        String decompressed = hackvertor.convert("<@gzip_decompress>" + compressed + "</@gzip_decompress>", hackvertor);
        assertEquals(input, decompressed);
    }
}