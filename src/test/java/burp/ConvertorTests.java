package burp;

import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class ConvertorTests {

    private final Hackvertor hackvertor;

    public ConvertorTests() {
        this.hackvertor = new Hackvertor();
        BurpExtender.setHelpers(new StubExtensionHelpers());
    }

    @Test
    void convertSpaceInTag() throws ParseException {
        String spaceInContent = "<@base64> <@/base64>";
        String converted = hackvertor.convert(spaceInContent, hackvertor);
        assertEquals("IA==", converted);
    }

    @Test
    void parseSpaces() throws ParseException {
        String spaceInContent = "<@base64> <@/base64>";
        LinkedList<Element> parsed = HackvertorParser.parse(spaceInContent);
        assertEquals(3, parsed.size());
        assertInstanceOf(Element.TextElement.class, parsed.get(1));
        assertEquals(" ", parsed.get(1).toString());
    }
}
