package hackvertor.parser;
import org.junit.jupiter.api.Test;

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
}