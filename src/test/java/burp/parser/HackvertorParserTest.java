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
            HackvertorParser.parse("’");
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
}