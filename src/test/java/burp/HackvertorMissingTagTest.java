package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test to verify that missing ending tags are returned as-is
 */
public class HackvertorMissingTagTest extends BaseHackvertorTest {
    
    @Test
    void testMissingEndingTagReturnsAsIs() {
        String input = "<@base64>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("<@base64>", result);
    }
    
    @Test
    void testMissingEndingTagWithContentReturnsAsIs() {
        String input = "<@base64>hello";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("<@base64>hello", result);
    }
    
    @Test
    void testMultipleMissingEndingTagsReturnAsIs() {
        String input = "<@base64><@hex>test";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("<@base64><@hex>test", result);
    }
    
    @Test
    void testMissingEndingTagWithAttributesReturnsAsIs() {
        String input = "<@repeat(3)>hello";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("<@repeat(3)>hello", result);
    }
    
    @Test
    void testPartiallyClosedNestedTagsProcessInnerTag() {
        // When outer tag is incomplete but inner tag is complete, 
        // the inner tag should still be processed
        String input = "<@base64>hello<@hex>world</@hex>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("<@base64>hello776f726c64", result);
    }
    
    @Test
    void testMixOfCompleteAndIncompleteTags() {
        // Complete tag should be processed, incomplete tag should remain as-is
        String input = "<@uppercase>hello</@uppercase> <@base64>world";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("HELLO <@base64>world", result);
    }
}