package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test to verify atbash cipher works with mixed case
 */
public class AtbashMixedCaseTest extends BaseHackvertorTest {
    
    @Test
    void testAtbashEncryptLowercase() {
        String input = "<@atbash_encrypt>hello</@atbash_encrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("svool", converted);
    }
    
    @Test
    void testAtbashEncryptUppercase() {
        String input = "<@atbash_encrypt>HELLO</@atbash_encrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("SVOOL", converted);
    }
    
    @Test
    void testAtbashEncryptMixedCase() {
        String input = "<@atbash_encrypt>Hello World</@atbash_encrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Svool Dliow", converted);
    }
    
    @Test
    void testAtbashDecryptLowercase() {
        String input = "<@atbash_decrypt>svool</@atbash_decrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("hello", converted);
    }
    
    @Test
    void testAtbashDecryptUppercase() {
        String input = "<@atbash_decrypt>SVOOL</@atbash_decrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("HELLO", converted);
    }
    
    @Test
    void testAtbashDecryptMixedCase() {
        String input = "<@atbash_decrypt>Svool Dliow</@atbash_decrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Hello World", converted);
    }
    
    @Test
    void testAtbashRoundTrip() {
        String original = "The Quick BROWN Fox Jumps Over The Lazy Dog 123!@#";
        String encrypted = hackvertor.convert("<@atbash_encrypt>" + original + "</@atbash_encrypt>", hackvertor);
        String decrypted = hackvertor.convert("<@atbash_decrypt>" + encrypted + "</@atbash_decrypt>", hackvertor);
        assertEquals(original, decrypted);
    }
    
    @Test
    void testAtbashPreservesNonAlpha() {
        String input = "<@atbash_encrypt>Hello123!@#World</@atbash_encrypt>";
        String converted = hackvertor.convert(input, hackvertor);
        assertEquals("Svool123!@#Dliow", converted);
    }
}