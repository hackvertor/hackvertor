package burp.parser;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;

public class Element {

    public static class StartTag extends Element {
        String identifier;
        ArrayList<String> arguments;
        public StartTag(String identifier, ArrayList<String> arguments) {
            this.identifier = identifier;
            this.arguments = arguments;
        }

        public String getIdentifier() {
            return identifier;
        }

        public ArrayList<String> getArguments() {
            return arguments;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("<@" + identifier);
            if(arguments.size() > 0){
                sb.append("(");
                for (int i = 0; i < arguments.size(); i++) {
                    if(i != 0) sb.append(",");
                    sb.append(arguments.get(i));
                }
                sb.append(")");
            }
            sb.append(">");
            return sb.toString();
        }
    }

    public static class SelfClosingTag extends StartTag {
        public SelfClosingTag(String identifier, ArrayList<String> arguments){
            super(identifier, arguments);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("<@" + identifier);
            if(arguments.size() > 0){
                sb.append("(");
                for (int i = 0; i < arguments.size(); i++) {
                    if(i != 0) sb.append(",");
                    if(StringUtils.isNumeric(arguments.get(i))){
                        sb.append(arguments.get(i));
                    }else {
                        sb.append("\"").append(arguments.get(i)).append("\"");
                    }
                }
                sb.append(")");
            }
            sb.append("/>");
            return sb.toString();
        }
    }

    public static class EndTag extends Element {
        String identifier;

        public EndTag(String identifier) {
            this.identifier = identifier;
        }

        public String getIdentifier() {
            return identifier;
        }

        @Override
        public String toString() {
            return "<@/" + identifier + ">";
        }
    }

    public static class TextElement extends Element{
        String content;
        public TextElement(String text){
            this.content = text;
        }

        public String getContent() {
            return content;
        }

        public void setContent(String content) {
            this.content = content;
        }

        @Override
        public String toString() {
            return content;
        }
    }
}
