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
}
