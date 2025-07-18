package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class GzipDebugTest extends BaseHackvertorTest {
    
    @Test
    void testSimpleGzipCompress() {
        String input = "test";
        String compressed = hackvertor.convert("<@gzip_compress>" + input + "</@gzip_compress>", hackvertor);
        System.out.println("Input: " + input);
        System.out.println("Compressed: " + compressed);
        System.out.println("Compressed length: " + (compressed != null ? compressed.length() : "null"));
        
        assertNotNull(compressed, "Compression should not return null");
        assertFalse(compressed.startsWith("Error:"), "Should not have error: " + compressed);
    }
    
    @Test
    void testGzipRoundTrip() {
        String input = "Hello World!";
        System.out.println("Original: " + input);
        
        String compressed = hackvertor.convert("<@gzip_compress>" + input + "</@gzip_compress>", hackvertor);
        System.out.println("Compressed: " + compressed);
        System.out.println("Compressed bytes: " + java.util.Arrays.toString(compressed.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
        
        String decompressed = hackvertor.convert("<@gzip_decompress>" + compressed + "</@gzip_decompress>", hackvertor);
        System.out.println("Decompressed: " + decompressed);
        System.out.println("Decompressed equals original: " + input.equals(decompressed));
        
        if (decompressed.startsWith("Error:")) {
            System.out.println("Decompression error: " + decompressed);
        }
    }
}