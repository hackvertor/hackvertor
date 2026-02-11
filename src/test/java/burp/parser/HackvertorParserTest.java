package burp.parser;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;

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
}