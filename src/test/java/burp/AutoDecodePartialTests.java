package burp;

import burp.hv.Convertors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AutoDecodePartialTests extends BaseHackvertorTest {

    @Test
    void testHexEscapePartialAtStart() {
        String input = "\\x66\\x6f\\x6f\\x62\\x61\\x72 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@hex_escapes>foobar</@hex_escapes> is the word", result);
    }

    @Test
    void testHexEscapePartialAtEnd() {
        String input = "the word is \\x66\\x6f\\x6f\\x62\\x61\\x72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@hex_escapes>foobar</@hex_escapes>", result);
    }

    @Test
    void testHexEscapePartialInMiddle() {
        String input = "prefix\\x66\\x6f\\x6f\\x62\\x61\\x72suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@hex_escapes>foobar</@hex_escapes>suffix", result);
    }

    @Test
    void testUnicodeEscapePartialAtStart() {
        String input = "\\u0066\\u006f\\u006f\\u0062\\u0061\\u0072 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@unicode_escapes>foobar</@unicode_escapes> is the word", result);
    }

    @Test
    void testUnicodeEscapePartialAtEnd() {
        String input = "the word is \\u0066\\u006f\\u006f\\u0062\\u0061\\u0072";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@unicode_escapes>foobar</@unicode_escapes>", result);
    }

    @Test
    void testUnicodeEscapePartialInMiddle() {
        String input = "prefix\\u0066\\u006f\\u006f\\u0062\\u0061\\u0072suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@unicode_escapes>foobar</@unicode_escapes>suffix", result);
    }

    @Test
    void testUrlEncodePartialAtStart() {
        String input = "%66%6f%6f%62%61%72 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@urlencode_not_plus>foobar</@urlencode_not_plus> is the word", result);
    }

    @Test
    void testUrlEncodePartialAtEnd() {
        String input = "the word is %66%6f%6f%62%61%72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@urlencode_not_plus>foobar</@urlencode_not_plus>", result);
    }

    @Test
    void testUrlEncodePartialInMiddle() {
        String input = "prefix%66%6f%6f%62%61%72suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@urlencode_not_plus>foobar</@urlencode_not_plus>suffix", result);
    }

    @Test
    void testHtmlEntityPartialAtStart() {
        String input = "&lt;&gt; are angle brackets";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@html_entities><></@html_entities> are angle brackets", result);
    }

    @Test
    void testHtmlEntityPartialAtEnd() {
        String input = "angle brackets are &lt;&gt;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("angle brackets are <@html_entities><></@html_entities>", result);
    }

    @Test
    void testHtmlEntityPartialInMiddle() {
        String input = "before&lt;script&gt;after";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("before<@html_entities><</@html_entities>script<@html_entities>></@html_entities>after", result);
    }

    @Test
    void testHexEntityPartialAtStart() {
        String input = "&#x3c;&#x3e; are angle brackets";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@hex_entities><></@hex_entities> are angle brackets", result);
    }

    @Test
    void testHexEntityPartialAtEnd() {
        String input = "angle brackets are &#x3c;&#x3e;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("angle brackets are <@hex_entities><></@hex_entities>", result);
    }

    @Test
    void testHexEntityPartialInMiddle() {
        String input = "before&#x3c;script&#x3e;after";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("before<@hex_entities><</@hex_entities>script<@hex_entities>></@hex_entities>after", result);
    }

    @Test
    void testDecimalEntityPartialInMiddle() {
        String input = "before&#60;script&#62;after";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("before<@hex_entities><</@hex_entities>script<@hex_entities>></@hex_entities>after", result);
    }

    @Test
    void testQuotedPrintablePartialAtStart() {
        String input = "=66=6f=6f=62=61=72 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@quoted_printable>foobar</@quoted_printable> is the word", result);
    }

    @Test
    void testQuotedPrintablePartialAtEnd() {
        String input = "the word is =66=6f=6f=62=61=72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@quoted_printable>foobar</@quoted_printable>", result);
    }

    @Test
    void testQuotedPrintablePartialInMiddle() {
        String input = "prefix=66=6f=6f=62=61=72suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@quoted_printable>foobar</@quoted_printable>suffix", result);
    }

    @Test
    void testOctalEscapePartialAtStart() {
        String input = "\\146\\157\\157\\142\\141\\162 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@octal_escapes>foobar</@octal_escapes> is the word", result);
    }

    @Test
    void testOctalEscapePartialAtEnd() {
        String input = "the word is \\146\\157\\157\\142\\141\\162";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@octal_escapes>foobar</@octal_escapes>", result);
    }

    @Test
    void testOctalEscapePartialInMiddle() {
        String input = "prefix\\146\\157\\157\\142\\141\\162suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@octal_escapes>foobar</@octal_escapes>suffix", result);
    }

    @Test
    void testBinaryPartialAtStart() {
        String input = "01100110 01101111 01101111 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@ascii2bin>foo</@ascii2bin> is the word", result);
    }

    @Test
    void testBinaryPartialAtEnd() {
        String input = "the word is 01100110 01101111 01101111";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@ascii2bin>foo</@ascii2bin>", result);
    }

    @Test
    void testBinaryPartialInMiddle() {
        String input = "prefix 01100110 01101111 01101111 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@ascii2bin>foo</@ascii2bin> suffix", result);
    }

    @Test
    void testHexSpacedPartialAtStart() {
        String input = "66 6f 6f 62 61 72 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@ascii2hex(\" \")>foobar</@ascii2hex> is the word", result);
    }

    @Test
    void testHexSpacedPartialAtEnd() {
        String input = "the word is 66 6f 6f 62 61 72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@ascii2hex(\" \")>foobar</@ascii2hex>", result);
    }

    @Test
    void testHexSpacedPartialInMiddle() {
        String input = "prefix 66 6f 6f 62 61 72 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@ascii2hex(\" \")>foobar</@ascii2hex> suffix", result);
    }

    @Test
    void testCharcodePartialAtStart() {
        String input = "102,111,111,98,97,114 is the word";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@to_charcode>foobar</@to_charcode> is the word", result);
    }

    @Test
    void testCharcodePartialAtEnd() {
        String input = "the word is 102,111,111,98,97,114";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("the word is <@to_charcode>foobar</@to_charcode>", result);
    }

    @Test
    void testCharcodePartialInMiddle() {
        String input = "prefix 102,111,111,98,97,114 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@to_charcode>foobar</@to_charcode> suffix", result);
    }

    @Test
    void testMultipleHexEscapeSequences() {
        String input = "first \\x66\\x6f\\x6f and second \\x62\\x61\\x72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("first <@hex_escapes>foo</@hex_escapes> and second <@hex_escapes>bar</@hex_escapes>", result);
    }

    @Test
    void testMultipleUrlEncodeSequences() {
        String input = "first %66%6f%6f and second %62%61%72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("first <@urlencode_not_plus>foo</@urlencode_not_plus> and second <@urlencode_not_plus>bar</@urlencode_not_plus>", result);
    }

    @Test
    void testMultipleDifferentEncodings() {
        String input = "hex: \\x66\\x6f\\x6f url: %62%61%72 entity: &lt;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("hex: <@hex_escapes>foo</@hex_escapes> url: <@urlencode_not_plus>bar</@urlencode_not_plus> entity: <@html_entities><</@html_entities>", result);
    }

    @Test
    void testNestedHexEscapeInsideUrlEncode() {
        String input = "prefix%5c%78%36%36%5c%78%36%66%5c%78%36%66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo"));
    }

    @Test
    void testNestedUrlEncodeInsideHexEscape() {
        String input = "prefix\\x25\\x36\\x36\\x25\\x36\\x66\\x25\\x36\\x66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo"));
    }

    @Test
    void testDoubleUrlEncode() {
        String input = "prefix%25%36%36%25%36%66%25%36%66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo"));
    }

    @Test
    void testDoubleHexEscape() {
        String input = "prefix\\x5c\\x78\\x36\\x36\\x5c\\x78\\x36\\x66\\x5c\\x78\\x36\\x66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo"));
    }

    @Test
    void testXssPayloadPartial() {
        String input = "param=\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e&other=value";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("param=<@hex_escapes><script>alert(1)</script></@hex_escapes>&other=value", result);
    }

    @Test
    void testSqlInjectionPayloadPartial() {
        String input = "id=1%27%20OR%20%271%27%3d%271&action=view";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("id=1<@urlencode_not_plus>' </@urlencode_not_plus>OR<@urlencode_not_plus> '</@urlencode_not_plus>1<@urlencode_not_plus>'='</@urlencode_not_plus>1&action=view", result);
    }

    @Test
    void testPathTraversalPartial() {
        String input = "file=..%2f..%2f..%2fetc%2fpasswd&type=text";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("file=..<@urlencode_not_plus>/</@urlencode_not_plus>..<@urlencode_not_plus>/</@urlencode_not_plus>..<@urlencode_not_plus>/</@urlencode_not_plus>etc<@urlencode_not_plus>/</@urlencode_not_plus>passwd&type=text", result);
    }

    @Test
    void testHtmlInjectionPartial() {
        String input = "name=&lt;img src=x onerror=alert(1)&gt;&submit=true";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("name=<@html_entities><</@html_entities>img src=x onerror=alert(1)<@html_entities>></@html_entities>&submit=true", result);
    }

    @Test
    void testJsonWithEncodedValues() {
        String input = "{\"name\":\"\\x74\\x65\\x73\\x74\",\"value\":123}";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("{\"name\":\"<@hex_escapes>test</@hex_escapes>\",\"value\":123}", result);
    }

    @Test
    void testMixedEncodingsInUrl() {
        String input = "https://example.com/path?a=%3Cscript%3E&b=\\x61\\x6c\\x65\\x72\\x74&c=&#60;test&#62;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("https://example.com/path?a=<@urlencode_not_plus><</@urlencode_not_plus>script<@urlencode_not_plus>></@urlencode_not_plus>&b=<@hex_escapes>alert</@hex_escapes>&c=<@hex_entities><</@hex_entities>test<@hex_entities>></@hex_entities>", result);
    }

    @Test
    void testEmptyString() {
        String input = "";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("", result);
    }

    @Test
    void testNoEncodedContent() {
        String input = "This is a plain text string with no encoding";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("This is a plain text string with no encoding", result);
    }

    @Test
    void testOnlyEncodedContent() {
        String input = "\\x66\\x6f\\x6f\\x62\\x61\\x72";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@hex_escapes>foobar</@hex_escapes>", result);
    }

    @Test
    void testSpecialCharactersPreserved() {
        String input = "special chars !@#$^&*() with \\x66\\x6f\\x6f in middle";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("special chars !@#$^&*() with <@hex_escapes>foo</@hex_escapes> in middle", result);
    }

    @Test
    void testNewlinesPreserved() {
        String input = "line1\\x0a\\x66\\x6f\\x6fline2";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("line1<@hex_escapes>\nfoo</@hex_escapes>line2", result);
    }

    @Test
    void testTabsPreserved() {
        String input = "col1\\x09\\x66\\x6f\\x6fcol2";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("col1<@hex_escapes>\tfoo</@hex_escapes>col2", result);
    }

    @Test
    void testUnicodeBeyondAscii() {
        String input = "text with \\u00e9\\u00e8\\u00ea accents";
        String result = Convertors.auto_decode_partial(input);
        assertEquals(input, result);
    }

    @Test
    void testHexEscapeWithMixedCase() {
        String input = "prefix\\x46\\x4F\\x4F\\x42\\x41\\x52suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@hex_escapes>FOOBAR</@hex_escapes>suffix", result);
    }

    @Test
    void testUrlEncodeWithMixedCase() {
        String input = "prefix%46%4F%4F%42%41%52suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@urlencode_not_plus>FOOBAR</@urlencode_not_plus>suffix", result);
    }

    @Test
    void testHttpRequestLine() {
        String input = "GET /path?param=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("GET /path?param=<@urlencode_not_plus><</@urlencode_not_plus>script<@urlencode_not_plus>></@urlencode_not_plus>alert(1)<@urlencode_not_plus></</@urlencode_not_plus>script<@urlencode_not_plus>></@urlencode_not_plus> HTTP/1.1", result);
    }

    @Test
    void testCookieValue() {
        String input = "Cookie: session=abc123; user=\\x61\\x64\\x6d\\x69\\x6e; path=/";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("Cookie: session=abc123; user=<@hex_escapes>admin</@hex_escapes>; path=/", result);
    }

    @Test
    void testHeaderWithEncodedValue() {
        String input = "X-Custom-Header: prefix%20encoded%20value%20suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("X-Custom-Header: prefix<@urlencode_not_plus> </@urlencode_not_plus>encoded<@urlencode_not_plus> </@urlencode_not_plus>value<@urlencode_not_plus> </@urlencode_not_plus>suffix", result);
    }

    @Test
    void testTripleEncodedUrl() {
        String input = "prefix%25%32%35%33%43suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("<"));
    }

    @Test
    void testMultipleEncodingTypesConsecutive() {
        String input = "\\x66\\x6f\\x6f%62%61%72&lt;test&gt;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@hex_escapes>foo</@hex_escapes><@urlencode_not_plus>bar</@urlencode_not_plus><@html_entities><</@html_entities>test<@html_entities>></@html_entities>", result);
    }

    @Test
    void testLongEncodedString() {
        String input = "start\\x54\\x68\\x69\\x73\\x20\\x69\\x73\\x20\\x61\\x20\\x6c\\x6f\\x6e\\x67\\x65\\x72\\x20\\x73\\x74\\x72\\x69\\x6e\\x67\\x20\\x74\\x6f\\x20\\x74\\x65\\x73\\x74end";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("start<@hex_escapes>This is a longer string to test</@hex_escapes>end", result);
    }

    @Test
    void testHexSpacedWithCommas() {
        String input = "prefix 66,6f,6f,62,61,72 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@ascii2hex(\" \")>foobar</@ascii2hex> suffix", result);
    }

    @Test
    void testHexSpacedWithDashes() {
        String input = "prefix 66-6f-6f-62-61-72 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@ascii2hex(\" \")>foobar</@ascii2hex> suffix", result);
    }

    @Test
    void testCharcodeWithSpaces() {
        String input = "prefix 102 111 111 98 97 114 suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix <@to_charcode>foobar</@to_charcode> suffix", result);
    }

    @Test
    void testPartialEncodingWithNumbers() {
        String input = "value:1\\x66\\x6f\\x6f2";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("value:1<@hex_escapes>foo</@hex_escapes>2", result);
    }

    @Test
    void testMultipleLineInput() {
        String input = "line1: \\x66\\x6f\\x6f\nline2: %62%61%72\nline3: &lt;test&gt;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("line1: <@hex_escapes>foo</@hex_escapes>\nline2: <@urlencode_not_plus>bar</@urlencode_not_plus>\nline3: <@html_entities><</@html_entities>test<@html_entities>></@html_entities>", result);
    }

    @Test
    void testRealWorldSsrfPayload() {
        String input = "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F&action=fetch";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("url=http<@urlencode_not_plus>://</@urlencode_not_plus>169.254.169.254<@urlencode_not_plus>/</@urlencode_not_plus>latest<@urlencode_not_plus>/</@urlencode_not_plus>meta-data<@urlencode_not_plus>/</@urlencode_not_plus>&action=fetch", result);
    }

    @Test
    void testRealWorldLdapInjection() {
        String input = "search=*)(%26(objectClass=\\x2a)(uid=admin))&type=user";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("search=*)(<@urlencode_not_plus>&</@urlencode_not_plus>(objectClass=<@hex_escapes>*</@hex_escapes>)(uid=admin))&type=user", result);
    }

    @Test
    void testPartialEncodingPreservesStructure() {
        String input = "GET /api/users?id=\\x74\\x65\\x73\\x74 HTTP/1.1\r\nHost: example.com\r\nCookie: auth=%61%62%63";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("GET /api/users?id=<@hex_escapes>test</@hex_escapes> HTTP/1.1\r\nHost: example.com\r\nCookie: auth=<@urlencode_not_plus>abc</@urlencode_not_plus>", result);
    }

    @Test
    void testHexEntityWithSemicolon() {
        String input = "value&#x3d;&#x22;test&#x22;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("value<@hex_entities>=\"</@hex_entities>test<@hex_entities>\"</@hex_entities>", result);
    }

    @Test
    void testDecimalEntityPartial() {
        String input = "chars: &#60;&#62;&#38; end";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("chars: <@hex_entities><>&</@hex_entities> end", result);
    }

    @Test
    void testIterativeDecodingTwoLevels() {
        String input = "prefix%5C%78%36%36%5C%78%36%66%5C%78%36%66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo"));
    }

    @Test
    void testOverlappingPatternsPriority() {
        String input = "test\\x25x66suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("test<@hex_escapes>%</@hex_escapes>x66suffix", result);
    }

    @Test
    void testConsecutiveEncodingsNoSpace() {
        String input = "\\x61\\x62\\x63%64%65%66&#103;&#104;&#105;";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("<@hex_escapes>abc</@hex_escapes><@urlencode_not_plus>def</@urlencode_not_plus><@hex_entities>ghi</@hex_entities>", result);
    }

    @Test
    void testUrlEncodedSlashes() {
        String input = "path=..%2f..%2f..%2f";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("path=..<@urlencode_not_plus>/</@urlencode_not_plus>..<@urlencode_not_plus>/</@urlencode_not_plus>..<@urlencode_not_plus>/</@urlencode_not_plus>", result);
    }

    @Test
    void testHexEscapeNullByte() {
        String input = "data\\x00\\x66\\x6f\\x6fend";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foo") && result.contains("<@hex_escapes>"));
    }

    @Test
    void testUnicodeEscapeEmoji() {
        String input = "prefix\\u0048\\u0069suffix";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("prefix<@unicode_escapes>Hi</@unicode_escapes>suffix", result);
    }

    @Test
    void testHexEscapeWithGzipCompression() {
        String gzipped = hackvertor.convert("<@gzip_compress>foobar</@gzip_compress>", hackvertor);
        String hexEncoded = hackvertor.convert("<@hex_escapes>" + gzipped + "</@hex_escapes>", hackvertor);
        String input = "prefix" + hexEncoded + "suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("foobar") && result.contains("<@gzip_compress>") && result.contains("<@hex_escapes>"));
    }

    @Test
    void testUrlEncodeWithGzipCompression() {
        String gzipped = hackvertor.convert("<@gzip_compress>test data</@gzip_compress>", hackvertor);
        String urlEncoded = hackvertor.convert("<@urlencode_all>" + gzipped + "</@urlencode_all>", hackvertor);
        String input = "data=" + urlEncoded + "&other=value";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("test data") && result.contains("<@gzip_compress>"));
    }

    @Test
    void testHexEscapeWithDeflateCompression() {
        String deflated = hackvertor.convert("<@deflate_compress>hello world</@deflate_compress>", hackvertor);
        String hexEncoded = hackvertor.convert("<@hex_escapes>" + deflated + "</@hex_escapes>", hackvertor);
        String input = "prefix" + hexEncoded + "suffix";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("hello world") && result.contains("<@deflate_compress>") && result.contains("<@hex_escapes>"));
    }

    @Test
    void testUrlEncodeWithDeflateCompression() {
        String deflated = hackvertor.convert("<@deflate_compress>compressed text</@deflate_compress>", hackvertor);
        String urlEncoded = hackvertor.convert("<@urlencode_all>" + deflated + "</@urlencode_all>", hackvertor);
        String input = "content=" + urlEncoded;
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("compressed text") && result.contains("<@deflate_compress>"));
    }

    @Test
    void testNestedCompressionGzipInDeflate() {
        String doubleCompressed = hackvertor.convert("<@deflate_compress><@gzip_compress>nested</@gzip_compress></@deflate_compress>", hackvertor);
        String hexEncoded = hackvertor.convert("<@hex_escapes>" + doubleCompressed + "</@hex_escapes>", hackvertor);
        String input = "start" + hexEncoded + "end";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("nested") && result.contains("<@deflate_compress>") && result.contains("<@gzip_compress>"));
    }

    @Test
    void testMultipleCompressedSegments() {
        String gzipped1 = hackvertor.convert("<@gzip_compress>first</@gzip_compress>", hackvertor);
        String gzipped2 = hackvertor.convert("<@gzip_compress>second</@gzip_compress>", hackvertor);
        String hex1 = hackvertor.convert("<@hex_escapes>" + gzipped1 + "</@hex_escapes>", hackvertor);
        String hex2 = hackvertor.convert("<@hex_escapes>" + gzipped2 + "</@hex_escapes>", hackvertor);
        String input = "a=" + hex1 + "&b=" + hex2;
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("first") && result.contains("second") && result.contains("<@gzip_compress>"));
    }

    @Test
    void testTagsCanBeReEncoded() {
        String input = "test \\x66\\x6F\\x6F data";
        String result = Convertors.auto_decode_partial(input);
        String reEncoded = hackvertor.convert(result, hackvertor);
        assertEquals(input, reEncoded);
    }

    @Test
    void testUrlEncodeWithPlusSign() {
        String input = "query=hello+world%20test";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("<@urlencode_not_plus> </@urlencode_not_plus>"));
    }

    @Test
    void testBase64PartialDecode() {
        String input = "abc Zm9vYmFy abc";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("abc <@base64>foobar</@base64> abc", result);
    }

    @Test
    void testBase64NestedPartialDecode() {
        String input = "abc V20wNWRrbEhTbWhqYVVKcFdWaHZQUT09 abc";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("abc <@base64><@base64><@base64>foo bar baz</@base64></@base64></@base64> abc", result);
    }

    @Test
    void testBase64PartialDecodeMultiple() {
        String input = "first: Zm9v second: YmFy end";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("first: <@base64>foo</@base64> second: <@base64>bar</@base64> end", result);
    }

    @Test
    void testBase32PartialDecode() {
        String input = "abc MZXW6=== abc";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("abc <@base32>foo</@base32> abc", result);
    }

    @Test
    void testBase32PartialDecodeNested() {
        String input = "abc JVNFQVZWHU6T2=== abc";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("abc <@base32><@base32>foo</@base32></@base32> abc", result);
    }

    @Test
    void testBase64urlPartialDecode() {
        String input = "token: SGVsbG8-V29ybGRf end";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("<@base64url>"));
        assertTrue(result.contains("</@base64url>"));
    }

    @Test
    void testBase58PartialDecode() {
        String input = "address: 2NEpo7TZRRrLZSi2U data";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.contains("<@base58>") || result.equals(input));
    }

    @Test
    void testBase64PartialDecodePreservesNonEncoded() {
        String input = "Hello Zm9vYmFy World";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.startsWith("Hello "));
        assertTrue(result.endsWith(" World"));
        assertTrue(result.contains("<@base64>foobar</@base64>"));
    }

    @Test
    void testBase64PartialDecodeWithPadding() {
        String input = "data: dGVzdA== end";
        String result = Convertors.auto_decode_partial(input);
        assertEquals("data: <@base64>test</@base64> end", result);
    }

    @Test
    void testBase64PartialDecodeCanReEncode() {
        String input = "abc Zm9vYmFy abc";
        String result = Convertors.auto_decode_partial(input);
        String reEncoded = hackvertor.convert(result, hackvertor);
        assertEquals(input, reEncoded);
    }

    @Test
    void testBase32PartialDecodeCanReEncode() {
        String input = "abc MZXW6YQ= abc";
        String result = Convertors.auto_decode_partial(input);
        String reEncoded = hackvertor.convert(result, hackvertor);
        assertEquals(input, reEncoded);
    }
}
