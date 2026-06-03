package burp;

import burp.hv.Convertors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SmartDecodeInvalidDataTests extends BaseHackvertorTest {

    @Test
    void dBase64urlTagWithImpossibleLengthDoesNotThrow() {
        String result = assertDoesNotThrow(() -> hackvertor.convert("<@d_base64url>a_cde</@d_base64url>", hackvertor));
        assertEquals("a_cde", result);
    }

    @Test
    void dBase64urlTagWithImpossibleLengthLongerDoesNotThrow() {
        String result = assertDoesNotThrow(() -> hackvertor.convert("<@d_base64url>____-___X</@d_base64url>", hackvertor));
        assertEquals("____-___X", result);
    }

    @Test
    void dBase64urlTagWithGarbageDoesNotThrow() {
        String result = assertDoesNotThrow(() -> hackvertor.convert("<@d_base64url>-_-_-_-_-</@d_base64url>", hackvertor));
        assertEquals("-_-_-_-_-", result);
    }

    @Test
    void dBase58TagWithInvalidCharactersDoesNotThrow() {
        String result = assertDoesNotThrow(() -> hackvertor.convert("<@d_base58>0OIl</@d_base58>", hackvertor));
        assertEquals("0OIl", result);
    }

    @Test
    void dBase58TagWithNonAlphabetCharactersDoesNotThrow() {
        String result = assertDoesNotThrow(() -> hackvertor.convert("<@d_base58>not_base58!</@d_base58>", hackvertor));
        assertEquals("not_base58!", result);
    }

    @Test
    void dBase32TagWithInvalidCharactersDoesNotThrow() {
        assertDoesNotThrow(() -> hackvertor.convert("<@d_base32>not base32!</@d_base32>", hackvertor));
    }

    @Test
    void smartDecodePartialWithBase64urlImpossibleLengthDoesNotThrow() {
        String input = "prefix ____-___X suffix";
        assertDoesNotThrow(() -> Convertors.auto_decode_partial(input));
    }

    @Test
    void smartDecodePartialWithBase58LikeDataDoesNotThrow() {
        String input = "id=000OOOIIIlll data";
        assertDoesNotThrow(() -> Convertors.auto_decode_partial(input));
    }

    @Test
    void smartDecodeFullWithBase64urlImpossibleLengthDoesNotThrow() {
        String input = "____-___X";
        assertDoesNotThrow(() -> hackvertor.convert("<@auto_decode_no_decrypt>" + input + "</@auto_decode_no_decrypt>", hackvertor));
    }

    @Test
    void smartDecodeFullWithMixedInvalidBaseLikeDataDoesNotThrow() {
        String input = "____-___X";
        assertDoesNotThrow(() -> hackvertor.convert("<@auto_decode>" + input + "</@auto_decode>", hackvertor));
    }

    @Test
    void smartDecodePartialDoesNotCorruptValidContentAroundInvalidBase64url() {
        String input = "before ____-___X after";
        String result = Convertors.auto_decode_partial(input);
        assertTrue(result.startsWith("before "));
        assertTrue(result.endsWith(" after"));
    }
}
