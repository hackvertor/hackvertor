package burp;

import burp.hv.Convertors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SmartPasteTests extends BaseHackvertorTest {

    @Test
    void smartDecodeDecodesBase64WrappedHexEntities() {
        String input = "JiN4Njg7JiN4NzQ7JiN4NzQ7JiN4NzA7JiN4NzM7JiN4M2E7JiN4MmY7JiN4MmY7JiN4NzA7JiN4NmY7JiN4NzI7JiN4NzQ7JiN4NzM7JiN4Nzc7JiN4Njk7JiN4Njc7JiN4Njc7JiN4NjU7JiN4NzI7JiN4MmU7JiN4NmU7JiN4NjU7JiN4NzQ7";
        String result = Convertors.smartDecode(input);
        assertEquals("<@base64><@hex_entities>https://portswigger.net</@hex_entities></@base64>", result);
    }

    @Test
    void smartDecodeFallsBackToPartialWhenFullDecodeDoesNothing() {
        String input = "abc Zm9vYmFy abc";
        String result = Convertors.smartDecode(input);
        assertEquals("abc <@base64>foobar</@base64> abc", result);
    }

    @Test
    void smartDecodeLeavesPlainTextUnchanged() {
        String input = "this is just plain text";
        String result = Convertors.smartDecode(input);
        assertEquals("this is just plain text", result);
    }
}
