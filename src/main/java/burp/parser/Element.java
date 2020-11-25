package burp.parser;

import java.util.ArrayList;

public class Element {

    public static class StartTag extends Element {
        String identifier;
        ArrayList<String> arguments;
        public StartTag(String identifier, ArrayList<String> arguments) {
            this.identifier = identifier;
            this.arguments = arguments;
        }

        @Override
        public String toString() {
            return "StartTag{" +
                    "identifier='" + identifier + '\'' +
                    ", arguments=" + arguments +
                    '}';
        }
    }

    public static class EndTag extends Element {
        String identifier;

        public EndTag(String identifier) {
            this.identifier = identifier;
        }

        @Override
        public String toString() {
            return "EndTag{" +
                    "identifier='" + identifier + '\'' +
                    '}';
        }
    }

    public static class TextElement extends Element{
        String content;
        public TextElement(String text){
            this.content = text;
        }

        @Override
        public String toString() {
            return "TextElement{" +
                    "content='" + content + '\'' +
                    '}';
        }
    }
}
