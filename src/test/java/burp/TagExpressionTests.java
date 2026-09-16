package burp;

import burp.hv.HackvertorExtension;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the check tag and the && / || / ! tag expressions built on top of it.
 */
public class TagExpressionTests extends BaseHackvertorTest {

    private String key;

    @BeforeEach
    void registerIsJsonCustomTag() throws Exception {
        HackvertorExtension.generalSettings.setBoolean("codeExecutionTagsEnabled", true);
        key = HackvertorExtension.tagCodeExecutionKey;

        JSONObject isJson = new JSONObject();
        isJson.put("tagName", "_isJson");
        isJson.put("language", "Python");
        isJson.put("code", "output = str(input.strip().startswith('{')).lower()");
        isJson.put("numberOfArgs", 0);
        hackvertor.setCustomTags(new JSONArray().put(isJson));
    }

    private String check(String input) {
        return check("isJson", input);
    }

    private String check(String tagName, String input) {
        //The tag name is quoted because a bare tag argument cannot contain an underscore.
        return "<@check('" + tagName + "','" + key + "')>" + input + "</@check>";
    }

    private String convert(String input) {
        return hackvertor.convert(input, hackvertor);
    }

    @Test
    void checkTagOnItsOwnReturnsTrueOrFalse() {
        assertEquals("true", convert(check("{}")));
        assertEquals("false", convert(check("nope")));
    }

    @Test
    void andOutputsRightHandSideWhenCheckPasses() {
        assertEquals("Zm9v", convert(check("{}") + " && <@base64>foo</@base64>"));
    }

    @Test
    void andOutputsNothingWhenCheckFails() {
        assertEquals("", convert(check("nope") + " && <@base64>foo</@base64>"));
    }

    @Test
    void orOutputsRightHandSideWhenCheckFails() {
        assertEquals("Zm9v", convert(check("nope") + " || <@base64>foo</@base64>"));
    }

    @Test
    void orOutputsNothingWhenCheckPasses() {
        assertEquals("", convert(check("{}") + " || <@base64>foo</@base64>"));
    }

    @Test
    void negationInvertsTheCheck() {
        assertEquals("Zm9v", convert("!" + check("nope") + " && <@base64>foo</@base64>"));
        assertEquals("", convert("!" + check("{}") + " && <@base64>foo</@base64>"));
    }

    @Test
    void doubleNegationIsSupported() {
        assertEquals("Zm9v", convert("!!" + check("{}") + " && <@base64>foo</@base64>"));
    }

    @Test
    void andBindsTighterThanOr() {
        //false || (true && base64) -> the base64 output
        assertEquals("Zm9v", convert(check("nope") + " || " + check("{}") + " && <@base64>foo</@base64>"));
        //true || (...) -> the truthy boolean, which renders as nothing, and the right hand side never runs
        assertEquals("", convert(check("{}") + " || " + check("nope") + " && <@base64>foo</@base64>"));
    }

    @Test
    void whitespaceAroundOperatorsIsOptional() {
        assertEquals("Zm9v", convert(check("{}") + "&&<@base64>foo</@base64>"));
        assertEquals("Zm9v", convert(check("{}") + "  \t &&  \t <@base64>foo</@base64>"));
    }

    @Test
    void aLineEndingOnAnOperatorContinuesOntoTheNextLine() {
        assertEquals("Zm9v", convert(check("{}") + " &&\n<@base64>foo</@base64>"));
        assertEquals("Zm9v", convert(check("nope") + " ||\n  <@base64>foo</@base64>"));
        assertEquals("Zm9v", convert(check("{}") + " &&\n!" + check("nope") + " &&\n<@base64>foo</@base64>"));
    }

    @Test
    void anOperatorStartingALineDoesNotContinueThePreviousLine() {
        //The first line is a complete expression, so it ends there.
        assertEquals("true\n&&\nZm9v", convert(check("{}") + "\n&&\n<@base64>foo</@base64>"));
    }

    @Test
    void erroringOperandIsFalsy() {
        //The unknown tag throws, which makes the operand falsy, so the fallback is used.
        assertEquals("YmFy", convert(check("{}") + " && <@unknown_tag_xyz>a</@unknown_tag_xyz> || <@base64>bar</@base64>"));
    }

    @Test
    void shortCircuitSkipsOperandsThatCannotChangeTheOutcome() {
        //Without short circuiting the unknown tag would turn the whole conversion into an error.
        String output = convert(check("nope") + " && <@unknown_tag_xyz>a</@unknown_tag_xyz>");
        assertEquals("", output);
        assertFalse(output.startsWith("Error:"));
    }

    @Test
    void expressionsWorkInsideOtherTags() {
        assertEquals("Zm9v", convert("<@base64>" + check("{}") + " && foo</@base64>"));
        assertEquals("", convert("<@base64>" + check("nope") + " && foo</@base64>"));
    }

    @Test
    void plainTextOperandsAreSupported() {
        assertEquals("foo", convert(check("{}") + " && foo"));
    }

    @Test
    void operatorsAreLiteralTextWithoutACheckTag() {
        assertEquals("Zm9v && 9dd4e461268c8034f5c8564e155c67a6",
                convert("<@base64>foo</@base64> && <@md5>x</@md5>"));
        assertEquals("Zm9v || 9dd4e461268c8034f5c8564e155c67a6",
                convert("<@base64>foo</@base64> || <@md5>x</@md5>"));
    }

    @Test
    void operatorCharactersInContentAreLeftAlone() {
        assertEquals("YSZi", convert("<@base64>a&b</@base64>"));
        assertEquals("YXxi", convert("<@base64>a|b</@base64>"));
        assertEquals("YSFi", convert("<@base64>a!b</@base64>"));
        assertEquals("a && b || !c", convert("a && b || !c"));
    }

    @Test
    void operatorCharactersInContentAreLeftAloneEvenWithACheckTag() {
        //The operators live inside the base64 body, which has no check tag of its own.
        assertEquals("YSFiICYmIGM=", convert(check("{}") + " && <@base64>a!b && c</@base64>"));
    }

    @Test
    void negationIsOnlyAnOperatorInPrefixPosition() {
        assertEquals("hello!", convert(check("{}") + " && hello!"));
    }

    @Test
    void customTagArgumentsFallBackToTheirDefaults() {
        JSONObject startsWith = new JSONObject();
        startsWith.put("tagName", "_startsWith");
        startsWith.put("language", "Python");
        startsWith.put("code", "output = str(input.startswith(prefix)).lower()");
        startsWith.put("numberOfArgs", 1);
        startsWith.put("argument1", "prefix");
        startsWith.put("argument1Type", "String");
        startsWith.put("argument1Default", "foo");
        hackvertor.setCustomTags(new JSONArray().put(startsWith));

        assertEquals("YmFy", convert("<@check(startsWith,'" + key + "')>foobar</@check> && <@base64>bar</@base64>"));
        assertEquals("", convert("<@check(startsWith,'" + key + "')>nope</@check> && <@base64>bar</@base64>"));
    }

    @Test
    void eachLineIsItsOwnExpression() {
        String input = check("isJson", "{}") + " && That is JSON\n"
                + "!" + check("isJson", "blah") + " && That is not JSON";
        assertEquals("That is JSON\nThat is not JSON", convert(input));
    }

    @Test
    void lineBreaksBetweenExpressionsArePreserved() {
        String input = check("isJson", "{}") + " && a\r\n"
                + "\n"
                + check("isJson", "{}") + " && b\n";
        assertEquals("a\r\n\nb\n", convert(input));
    }

    @Test
    void anExpressionDoesNotSpanALineBreak() {
        //The && on the second line has no check tag of its own, so it stays literal text.
        String input = check("isJson", "{}") + " && a\n"
                + "b && c";
        assertEquals("a\nb && c", convert(input));
    }

    @Test
    void lineBreaksInsideATagBelongToThatTag() {
        assertEquals("YQpi", convert(check("isJson", "{}") + " && <@base64>a\nb</@base64>"));
    }

    @Test
    void isJsonRecognisesObjectsAndArrays() {
        assertEquals("true", convert("<@isJson>{\"a\":1}</@isJson>"));
        assertEquals("true", convert("<@isJson>  [1, 2, 3]  </@isJson>"));
        assertEquals("false", convert("<@isJson>plain text</@isJson>"));
        assertEquals("false", convert("<@isJson>{\"a\":</@isJson>"));
        assertEquals("false", convert("<@isJson></@isJson>"));
    }

    @Test
    void isNumericRecognisesDecimalNumbers() {
        assertEquals("true", convert("<@isNumeric>42</@isNumeric>"));
        assertEquals("true", convert("<@isNumeric>-1.5</@isNumeric>"));
        assertEquals("true", convert("<@isNumeric>+2e10</@isNumeric>"));
        assertEquals("true", convert("<@isNumeric> 7 </@isNumeric>"));
        assertEquals("false", convert("<@isNumeric>1a</@isNumeric>"));
        assertEquals("false", convert("<@isNumeric>0x1f</@isNumeric>"));
        assertEquals("false", convert("<@isNumeric></@isNumeric>"));
    }

    @Test
    void checkCanCallBuiltInTags() {
        assertEquals("Zm9v", convert(check("isJson", "{\"a\":1}") + " && <@base64>foo</@base64>"));
        assertEquals("", convert(check("isJson", "plain text") + " && <@base64>foo</@base64>"));
        assertEquals("Zm9v", convert(check("isNumeric", "42") + " && <@base64>foo</@base64>"));
        assertEquals("Zm9v", convert("!" + check("isNumeric", "nope") + " && <@base64>foo</@base64>"));
    }

    @Test
    void checkPrefersTheBuiltInTagOverAnUnderscoredCustomTag() {
        //The built in isJson answers a bare name, the custom tag needs its "_" prefix.
        assertEquals("false", convert(check("isJson", "nope")));
        assertEquals("true", convert(check("_isJson", "{}")));
    }

    @Test
    void wrongExecutionKeyIsRejected() {
        String output = convert("<@check(isJson,'00000000000000000000000000000000')>{}</@check>");
        assertTrue(output.contains("Incorrect tag code execution key"), output);
    }

    @Test
    void missingTagIsReported() {
        String output = convert("<@check(nopeNotATag,'" + key + "')>{}</@check>");
        assertTrue(output.contains("Unknown tag"), output);
    }

    @Test
    void codeExecutionMustBeEnabled() throws Exception {
        HackvertorExtension.generalSettings.setBoolean("codeExecutionTagsEnabled", false);
        String output = convert(check("{}"));
        assertTrue(output.contains("Code execution tags are disabled by default"), output);
    }
}
