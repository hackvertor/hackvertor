package burp.parser;

import org.apache.commons.lang3.StringUtils;
import org.unbescape.java.JavaEscape;

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
                    String argument = arguments.get(i);
                    if((argument.startsWith("0x") && argument.matches("^0x[0-9a-fA-F]+$")) || (argument.startsWith("-") && StringUtils.isNumeric(argument.substring(1))) || StringUtils.isNumeric(argument) || argument.equals("true") || argument.equals("false"))
                        sb.append(argument);
                    else
                        sb.append("'" + JavaEscape.escapeJava(argument).replaceAll("'","\\\\'") + "'");
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
                    String argument = arguments.get(i);
                    if((argument.startsWith("-") && StringUtils.isNumeric(argument.substring(1))) || StringUtils.isNumeric(argument) || argument.equals("true") || argument.equals("false")) {
                        sb.append(argument);
                    } else {
                        sb.append("'").append(arguments.get(i).replaceAll("'","\\\\'")).append("'");
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
            return "</@" + identifier + ">";
        }
    }

    /**
     * A tag expression operator (&&, || or !).
     *
     * Extends TextElement so that every existing consumer that is unaware of expressions
     * treats an operator as the literal text it was parsed from. Expressions are only
     * evaluated when a check tag is present, see burp.hv.TagExpressions.
     */
    public static class Operator extends TextElement {
        public enum Type {
            AND("&&"), OR("||"), NOT("!");

            private final String symbol;

            Type(String symbol) {
                this.symbol = symbol;
            }

            public String getSymbol() {
                return symbol;
            }
        }

        private final Type type;

        public Operator(Type type) {
            super(type.getSymbol());
            this.type = type;
        }

        public Type getType() {
            return type;
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
