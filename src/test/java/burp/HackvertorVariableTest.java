package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test to verify Hackvertor variable functionality
 */
public class HackvertorVariableTest extends BaseHackvertorTest {
    
    @Test
    void testSetAndGetVariable() {
        // Basic set and get variable
        String input = "<@set_variable1(false)>foo</@set_variable1>\n\n<@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("foo\n\nfoo", result);
    }
    
    @Test
    void testGetVariableBeforeSet() {
        // Get variable can be used before set variable
        String input = "<@get_variable1/>\n\n<@set_variable1(false)>foo</@set_variable1>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("foo\n\nfoo", result);
    }
    
    @Test
    void testMultipleVariables() {
        // Test multiple different variables
        String input = "<@set_variable1(false)>foo</@set_variable1>\n" +
                       "<@set_variable2(false)>bar</@set_variable2>\n" +
                       "<@get_variable1/> <@get_variable2/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("foo\nbar\nfoo bar", result);
    }
    
    @Test
    void testVariableOverwrite() {
        // Test overwriting a variable
        String input = "<@set_variable1(false)>foo</@set_variable1>\n" +
                       "<@set_variable1(false)>bar</@set_variable1>\n" +
                       "<@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("foo\nbar\nbar", result);
    }
    
    @Test
    void testVariableWithTags() {
        // Test setting a variable with tag content
        String input = "<@set_variable1(false)><@base64>test</@base64></@set_variable1>\n" +
                       "<@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("dGVzdA==\ndGVzdA==", result);
    }
    
    @Test
    void testVariableInExpression() {
        // Test using variable content in another tag
        String input = "<@set_variable1(false)>hello</@set_variable1>\n" +
                       "<@uppercase><@get_variable1/></@uppercase>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("hello\nHELLO", result);
    }
    
    @Test
    void testMultipleGetSameVariable() {
        // Test getting the same variable multiple times
        String input = "<@set_variable1(false)>test</@set_variable1>\n" +
                       "<@get_variable1/> <@get_variable1/> <@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("test\ntest test test", result);
    }
    
    @Test
    void testVariableWithComplexContent() {
        // Test variable with complex nested content
        String input = "<@set_variable1(false)><@hex><@uppercase>abc</@uppercase></@hex></@set_variable1>\n" +
                       "Result: <@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("414243\nResult: 414243", result);
    }
    
    @Test
    void testEmptyVariable() {
        // Test setting an empty variable
        String input = "<@set_variable1(false)></@set_variable1>\n" +
                       "Value: '<@get_variable1/>'";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("\nValue: ''", result);
    }
    
    @Test
    void testVariableWithBooleanTrue() {
        // Test variable with boolean parameter set to true
        String input = "<@set_variable1(true)>foo</@set_variable1>\n" +
                       "<@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        // When boolean is true, it might affect output differently
        // Based on the expected behavior, adjust this assertion
        assertEquals("foo\nfoo", result);
    }
    
    @Test
    void testGetUndefinedVariable() {
        // Test getting a variable that was never set
        String input = "<@get_undefined_variable/>";
        String result = hackvertor.convert(input, hackvertor);
        // Undefined variables return null
        assertEquals("null", result);
    }
    
    @Test
    void testVariableAcrossMultipleLines() {
        // Test variable with multiline content
        String input = "<@set_variable1(false)>line1\nline2\nline3</@set_variable1>\n" +
                       "<@get_variable1/>";
        String result = hackvertor.convert(input, hackvertor);
        assertEquals("line1\nline2\nline3\nline1\nline2\nline3", result);
    }
}