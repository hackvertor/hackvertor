import burp.parser.HackvertorParser;
import burp.parser.ParseException;

public class TestParser {
    public static void main(String[] args) throws ParseException {
        HackvertorParser.parse("你好世界");
        HackvertorParser.parse("こんにちは、世界");
    }
}
