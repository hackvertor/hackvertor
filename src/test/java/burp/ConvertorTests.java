package burp;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ConvertorTests extends BaseHackvertorTest {

    @Test
    void convertSpaceInTag() {
        String spaceInContent = "<@base64> </@base64>";
        String converted = hackvertor.convert(spaceInContent, hackvertor);
        assertEquals("IA==", converted);
    }

    @Test
    void testBase64Encoding() {
        String input = "<@base64>test</@base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("dGVzdA==", converted);
    }
    
    @Test
    void testSimpleUppercase() {
        String input = "<@uppercase>hello</@uppercase>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("HELLO", converted);
    }

    @Test
    void testSpaceInAttribute(){
        String plaintext = "<@ascii2hex('')>abcd</@ascii2hex>";
        assertEquals("61626364", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex(' ')>abcd</@ascii2hex>";
        assertEquals("61 62 63 64", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex('  ')>abcd</@ascii2hex>";
        assertEquals("61  62  63  64", hackvertor.convert(plaintext, hackvertor));
    }

    // Encode Category Tests
    @Test
    void testBase32Encoding() {
        String input = "<@base32>Hello</@base32>";
        String converted = hackvertor.convert(input, hackvertor);
        assertNotNull(converted, "Conversion returned null");
        if (converted.startsWith("Error:")) {
            fail("Conversion failed with error: " + converted);
        }
        assertEquals("JBSWY3DP", converted);
    }

    @Test
    void testBase58Encoding() {
        String input = "<@base58>Hello</@base58>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("9Ajdvzr", converted);
    }

    @Test
    void testBase64UrlEncoding() {
        String input = "<@base64url>Hello World!</@base64url>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("SGVsbG8gV29ybGQh", converted);
    }

    @Test
    void testHtmlEntities() {
        String input = "<@html_entities><script>alert('XSS')</script></@html_entities>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("&lt;script&gt;alert&#40;&#39;XSS&#39;&#41;&lt;&#47;script&gt;", converted);
    }

    @Test
    void testHexEncoding() {
        String input = "<@hex>ABC</@hex>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("414243", converted);
    }

    @Test
    void testHexEntities() {
        String input = "<@hex_entities>ABC</@hex_entities>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("&#x41;&#x42;&#x43;", converted);
    }

    @Test
    void testDecEntities() {
        String input = "<@dec_entities>ABC</@dec_entities>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("&#65;&#66;&#67;", converted);
    }

    @Test
    void testUrlEncode() {
        String input = "<@urlencode>Hello World!</@urlencode>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello+World%21", converted);
    }

    @Test
    void testUrlEncodeAll() {
        String input = "<@urlencode_all>ABC</@urlencode_all>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("%41%42%43", converted);
    }

    @Test
    void testJsString() {
        String input = "<@js_string>Hello\"World'</@js_string>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello\\\"World'", converted);
    }

    // Decode Category Tests
    @Test
    void testBase32Decoding() {
        String input = "<@d_base32>JBSWY3DP</@d_base32>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello", converted);
    }

    @Test
    void testBase58Decoding() {
        String input = "<@d_base58>9Ajdvzr</@d_base58>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello", converted);
    }

    @Test
    void testBase64Decoding() {
        String input = "<@d_base64>SGVsbG8gV29ybGQ=</@d_base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello World", converted);
    }

    @Test
    void testBase64UrlDecoding() {
        String input = "<@d_base64url>SGVsbG8gV29ybGQh</@d_base64url>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello World!", converted);
    }

    @Test
    void testHtmlEntitiesDecoding() {
        String input = "<@d_html_entities>&lt;script&gt;</@d_html_entities>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("<script>", converted);
    }

    @Test
    void testUrlDecoding() {
        String input = "<@d_url>Hello+World%21</@d_url>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello World!", converted);
    }

    @Test
    void testUtf7Decoding() {
        // Basic text
        assertEquals("Hello", hackvertor.convert("<@d_utf7>Hello</@d_utf7>", hackvertor));
        
        // Special characters
        assertEquals("£", hackvertor.convert("<@d_utf7>+AKM-</@d_utf7>", hackvertor));
        assertEquals("€", hackvertor.convert("<@d_utf7>+IKw-</@d_utf7>", hackvertor));
        assertEquals("Hi Mom ☺", hackvertor.convert("<@d_utf7>Hi Mom +Jjo-</@d_utf7>", hackvertor));
        assertEquals("日本語", hackvertor.convert("<@d_utf7>+ZeVnLIqe-</@d_utf7>", hackvertor));
        
        // Plus sign handling
        assertEquals("1+1=2", hackvertor.convert("<@d_utf7>1+-1=2</@d_utf7>", hackvertor));
        
        // Unicode characters
        assertEquals("A≢Α", hackvertor.convert("<@d_utf7>A+ImI-+A5E-</@d_utf7>", hackvertor));
        
        // ASCII special characters
        assertEquals("!", hackvertor.convert("<@d_utf7>+ACE-</@d_utf7>", hackvertor));
        assertEquals("@", hackvertor.convert("<@d_utf7>+AEA-</@d_utf7>", hackvertor));
        
        // Test case from the original: foo bar
        assertEquals("foo bar", hackvertor.convert("<@d_utf7>+AGY-+AG8-+AG8-+ACA-+AGI-+AGE-+AHI-</@d_utf7>", hackvertor));
    }

    @Test
    void testUtf7Encoding() {
        // Test with default exclusion pattern (alphanumeric and common ASCII)
        // Note: backslashes need to be double-escaped in Java strings for the regex pattern
        String defaultPattern = "[\\\\s\\\\t\\\\r\\'(),-./:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+!]";
        // Test case from user - abc<> with default pattern
        // Note: <> are grouped together in encoding
        String input = "<@utf7('" + defaultPattern + "')>abc<></@utf7>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("abc+ADwAPg-", converted);
        
        // Test special characters that should be encoded (grouped)
        input = "<@utf7('" + defaultPattern + "')><>&\"</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+ADwAPgAmACI-", converted);
        
        // Test mixed content with excluded and encoded characters
        input = "<@utf7('" + defaultPattern + "')>Hello <script></@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello +ADw-script+AD4-", converted);
        
        // Test with only alphanumeric exclusion (grouped)
        String alphaNumPattern = "[A-Za-z0-9]";
        input = "<@utf7('" + alphaNumPattern + "')>abc !@#</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("abc+ACAAIQBAACM-", converted);
        
        // Test empty exclusion pattern (encode everything as group)
        input = "<@utf7('')>abc</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+AGEAYgBj-", converted);
        
        // Test with spaces and special chars excluded
        String spacesPattern = "[\\\\s]";
        input = "<@utf7('" + spacesPattern + "')>a b c</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+AGE- +AGI- +AGM-", converted);
        
        // Test unicode characters (should always be encoded as group)
        input = "<@utf7('" + defaultPattern + "')>Hello 世界</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello +ThZ1TA-", converted);
        
        // Test HTML entities mixed with text
        input = "<@utf7('" + defaultPattern + "')>&lt;div&gt;</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+ACY-lt+ADs-div+ACY-gt+ADs-", converted);
        
        // Test punctuation marks (grouped)
        input = "<@utf7('[A-Za-z0-9]')>Hello, World!</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello+ACwAIA-World+ACE-", converted);
        
        // Test consecutive special characters (grouped)
        input = "<@utf7('" + defaultPattern + "')><<<>>></@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+ADwAPAA8AD4APgA+-", converted);
    }

    @Test 
    void testUtf7EncodingRoundTrip() {
        // Test that encoding and then decoding produces the original text
        String[] testStrings = {
            "Hello World",
            "<script>alert('XSS')</script>",
            "Special chars: & < > \" '",
            "Unicode: 日本語 émojis 😀",
            "Mixed: abc<>123",
            "Symbols: !@#$%^&*()",
            "HTML: <div class=\"test\">&nbsp;</div>"
        };

        String defaultPattern = "[\\\\s\\\\t\\\\r\\'(),-./:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+!]";
        
        for (String original : testStrings) {
            // Encode
            String encoded = hackvertor.convert("<@utf7('" + defaultPattern + "')>" + original + "</@utf7>", hackvertor);
            // Decode
            String decoded = hackvertor.convert("<@d_utf7>" + encoded + "</@d_utf7>", hackvertor);
            assertEquals(original, decoded, "Round-trip failed for: " + original);
        }
    }

    @Test
    void testUtf7EncodingEdgeCases() {
        String defaultPattern = "[\\\\s\\\\t\\\\r\\'(),-./:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+!]";
        
        // Test empty string
        String input = "<@utf7('" + defaultPattern + "')></@utf7>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("", converted);
        
        // Test single special character
        input = "<@utf7('" + defaultPattern + "')><</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+ADw-", converted);
        
        // Test plus sign handling (plus is special in UTF-7)
        input = "<@utf7('[A-Za-z0-9]')>a+b</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("a+ACs-b", converted);
        
        // Test already UTF-7 encoded content (should pass through)
        input = "<@utf7('" + defaultPattern + "')>+ADw-</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("+-ADw-", converted);  // '+' becomes '+-', rest are excluded
        
        // Test newlines and tabs
        input = "<@utf7('[A-Za-z0-9]')>line1\nline2\ttab</@utf7>";
        converted = hackvertor.convert(input, hackvertor);
        assertEquals("line1+AAo-line2+AAk-tab", converted);
    }

    // Hash Category Tests
    @Test
    void testMd5Hash() {
        String input = "<@md5>test</@md5>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("098f6bcd4621d373cade4e832627b4f6", converted);
    }

    @Test
    void testSha1Hash() {
        String input = "<@sha1>test</@sha1>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", converted);
    }

    @Test
    void testSha256Hash() {
        String input = "<@sha256>test</@sha256>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", converted);
    }

    @Test
    void testSha512Hash() {
        String input = "<@sha512>test</@sha512>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", converted);
    }

    // String Category Tests
    @Test
    void testUppercase() {
        String input = "<@uppercase>hello world</@uppercase>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("HELLO WORLD", converted);
    }

    @Test
    void testLowercase() {
        String input = "<@lowercase>HELLO WORLD</@lowercase>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("hello world", converted);
    }

    @Test
    void testCapitalise() {
        String input = "<@capitalise>hello world</@capitalise>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello world", converted);
    }

    @Test
    void testReverse() {
        String input = "<@reverse>Hello</@reverse>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("olleH", converted);
    }

    @Test
    void testLength() {
        String input = "<@length>Hello World</@length>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("11", converted);
    }

    @Test
    void testSubstring() {
        String input = "<@substring(0,5)>Hello World</@substring>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello", converted);
    }

    @Test
    void testReplace() {
        String input = "<@replace('World','Universe')>Hello World</@replace>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello Universe", converted);
    }

    @Test
    void testRepeat() {
        String input = "<@repeat(3)>A</@repeat>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("AAA", converted);
    }

    // Convert Category Tests
    @Test
    void testDec2Hex() {
        String input = "<@dec2hex('(\\\\d+)')>255</@dec2hex>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("ff", converted);
    }

    @Test
    void testHex2Dec() {
        String input = "<@hex2dec('((?:0x)?[a-f0-9]+)')>ff</@hex2dec>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("255", converted);
    }

    @Test
    void testDec2Bin() {
        String input = "<@dec2bin('(\\\\d+)')>10</@dec2bin>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("1010", converted);
    }

    @Test
    void testBin2Dec() {
        String input = "<@bin2dec('([0-1]+)')>1010</@bin2dec>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("10", converted);
    }

    @Test
    void testAscii2Hex() {
        String input = "<@ascii2hex>ABC</@ascii2hex>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("414243", converted);
    }

    @Test
    void testHex2Ascii() {
        String input = "<@hex2ascii>414243</@hex2ascii>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("ABC", converted);
    }

    // Encryption/Decryption Tests
    @Test
    void testXorEncryption() {
        String input = "<@xor('key')>Hello</@xor>";
        String converted = hackvertor.convert(input, hackvertor);
        // XOR is reversible, so we'll test round-trip
        String decrypted = hackvertor.convert("<@xor('key')>" + converted + "</@xor>", hackvertor);
        assertEquals("Hello", decrypted);
    }

    @Test
    void testRotN() {
        String input = "<@rotN(13)>Hello</@rotN>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Uryyb", converted);
    }

    @Test
    void testAtbashEncrypt() {
        String input = "<@atbash_encrypt>Hello</@atbash_encrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Svool", converted);
    }

    @Test
    void testGzipCompress() {
        String input = "Hello World! This is a test string for compression.";
        String compressed = hackvertor.convert("<@gzip_compress>" + input + "</@gzip_compress>", hackvertor);
        String decompressed = hackvertor.convert("<@gzip_decompress>"+compressed+"</@gzip_decompress>", hackvertor);
        assertNotNull(compressed);
        assertNotEquals(input, compressed);
        
        // Compressed output should not be empty
        assertFalse(compressed.isEmpty(), "Compressed output should not be empty");

        assertEquals(input, decompressed);
    }

    // HMAC Tests
    @Test
    void testHmacSha256() {
        String input = "<@hmac_sha256('secret')>message</@hmac_sha256>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b", converted);
    }

    // Math Category Tests
    @Test
    void testRange() {
        String input = "<@range(1,5,1)></@range>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("1,2,3,4,5", converted);
    }

    @Test
    void testArithmetic() {
        String input = "<@arithmetic(10,'+',',')>10</@arithmetic>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("20", converted);
    }

    @Test
    void testZeropad() {
        String input = "<@zeropad(',',5)>42</@zeropad>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("00042", converted);
    }

    // Nested Tags Test
    @Test
    void testNestedTags() {
        String input = "<@uppercase><@base64>test</@base64></@uppercase>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("DGVZDA==", converted);
    }

    // Multiple Same Tags Test
    @Test
    void testMultipleSameTags() {
        String input = "<@base64>Hello</@base64> <@base64>World</@base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("SGVsbG8= V29ybGQ=", converted);
    }
}