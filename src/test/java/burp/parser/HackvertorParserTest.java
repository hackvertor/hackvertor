package burp.parser;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class HackvertorParserTest {

    @Test
    void parseUnicode1() {
        assertDoesNotThrow(() -> {
            HackvertorParser.parse("你好世界");
        });
    }
    @Test
    void parseUnicode2() {
        assertDoesNotThrow(() -> {
            HackvertorParser.parse("'");
        });
    }

    @Test
    void parseSpaces() throws ParseException {
        String spaceInContent = "<@base64> </@base64>";
        LinkedList<Element> parsed = HackvertorParser.parse(spaceInContent);
        assertEquals(3, parsed.size());
        assertInstanceOf(Element.TextElement.class, parsed.get(1));
        assertEquals(" ", parsed.get(1).toString());
    }

    @Test
    void parseSelfClosingTagWithSpace() throws ParseException {
        String tagWithSpace = "<@get_x />";
        LinkedList<Element> parsed = HackvertorParser.parse(tagWithSpace);
        assertEquals(1, parsed.size());
        assertInstanceOf(Element.SelfClosingTag.class, parsed.get(0));
        assertEquals("get_x", ((Element.SelfClosingTag) parsed.get(0)).getIdentifier());
    }

    @Test
    void parseSelfClosingTagWithMultipleSpaces() throws ParseException {
        String tagWithSpaces = "<@get_x   />";
        LinkedList<Element> parsed = HackvertorParser.parse(tagWithSpaces);
        assertEquals(1, parsed.size());
        assertInstanceOf(Element.SelfClosingTag.class, parsed.get(0));
    }

    @Test
    void parseSelfClosingTagWithTab() throws ParseException {
        String tagWithTab = "<@get_x\t/>";
        LinkedList<Element> parsed = HackvertorParser.parse(tagWithTab);
        assertEquals(1, parsed.size());
        assertInstanceOf(Element.SelfClosingTag.class, parsed.get(0));
    }

    @Test
    void parseSelfClosingTagWithArgsAndSpace() throws ParseException {
        String tagWithArgsAndSpace = "<@tag(arg1,arg2) />";
        LinkedList<Element> parsed = HackvertorParser.parse(tagWithArgsAndSpace);
        assertEquals(1, parsed.size());
        assertInstanceOf(Element.SelfClosingTag.class, parsed.get(0));
    }

    @Test
    void parseExpressionOperators() throws ParseException {
        LinkedList<Element> parsed = HackvertorParser.parse("<@check(a)>{}</@check> && !<@base64>foo</@base64>");
        assertEquals(Element.Operator.Type.AND, operatorAt(parsed, "&&").getType());
        assertEquals(Element.Operator.Type.NOT, operatorAt(parsed, "!").getType());
        assertEquals(Element.Operator.Type.OR,
                operatorAt(HackvertorParser.parse("a || b"), "||").getType());
    }

    @Test
    void operatorsAreTextElementsSoTheyRoundTrip() throws ParseException {
        String[] inputs = {
                "a && b || !c",
                "a & b | c ! d",
                "&&",
                "||!&|",
                "1 && 2 || 3"
        };
        for (String input : inputs) {
            LinkedList<Element> parsed = HackvertorParser.parse(input);
            assertEquals(input, parsed.stream().map(Object::toString).collect(Collectors.joining()));
            for (Element element : parsed) {
                assertInstanceOf(Element.TextElement.class, element, input);
            }
        }
        String withTags = "<@base64>a!b && c</@base64>";
        assertEquals(withTags, HackvertorParser.parse(withTags).stream()
                .map(Object::toString).collect(Collectors.joining()));
    }

    @Test
    void loneOperatorCharactersStayText() throws ParseException {
        LinkedList<Element> parsed = HackvertorParser.parse("a&b");
        assertEquals(3, parsed.size());
        assertEquals("a&b", parsed.stream().map(Object::toString).collect(Collectors.joining()));
        assertFalse(parsed.get(1) instanceof Element.Operator);
    }

    private static Element.Operator operatorAt(LinkedList<Element> parsed, String symbol) {
        return parsed.stream()
                .filter(element -> element instanceof Element.Operator)
                .map(element -> (Element.Operator) element)
                .filter(operator -> operator.getContent().equals(symbol))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No " + symbol + " operator found"));
    }
}