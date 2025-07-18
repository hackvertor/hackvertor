package burp;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic tests for Hackvertor tags that work reliably in test environment
 */
public class ConvertorTestsBasic extends BaseHackvertorTest {

    // Working Encode Tests
    @Test
    void testBase64Encoding() {
        String input = "<@base64>test</@base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("dGVzdA==", converted);
    }

    @Test
    void testBase64UrlEncoding() {
        String input = "<@base64url>Hello World!</@base64url>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("SGVsbG8gV29ybGQh", converted);
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

    // Working String Tests
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

    // Working Hash Tests
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

    // Working Convert Tests
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

    // Working Encryption Tests
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

    // Test nested tags
    @Test
    void testNestedTags() {
        String input = "<@uppercase><@base64>test</@base64></@uppercase>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("DGVZDA==", converted);
    }

    // Test multiple same tags
    @Test
    void testMultipleSameTags() {
        String input = "<@base64>Hello</@base64> <@base64>World</@base64>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("SGVsbG8= V29ybGQ=", converted);
    }

    // Test space in attribute
    @Test
    void testSpaceInAttribute(){
        String plaintext = "<@ascii2hex('')>abcd</@ascii2hex>";
        assertEquals("61626364", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex(' ')>abcd</@ascii2hex>";
        assertEquals("61 62 63 64", hackvertor.convert(plaintext, hackvertor));
        plaintext = "<@ascii2hex('  ')>abcd</@ascii2hex>";
        assertEquals("61  62  63  64", hackvertor.convert(plaintext, hackvertor));
    }
}