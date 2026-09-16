package burp.hv;

import burp.parser.Element;
import burp.parser.ParseException;

import java.util.ArrayList;
import java.util.List;

/**
 * Tag expressions: two or more operands combined with {@code &&} or {@code ||}, optionally
 * negated with {@code !}, for example
 *
 * <pre>&lt;@check(isJson,'&lt;key&gt;')&gt;{}&lt;/@check&gt; &amp;&amp; &lt;@base64&gt;foo&lt;/@base64&gt;</pre>
 *
 * <ul>
 *     <li>{@code A && B} outputs B when A is truthy, otherwise A.</li>
 *     <li>{@code A || B} outputs A when A is truthy, otherwise B.</li>
 *     <li>{@code &&} binds tighter than {@code ||}, so {@code A || B && C} means {@code A || (B && C)}.</li>
 *     <li>Evaluation short circuits, an operand whose result cannot change the outcome is never run.</li>
 *     <li>Falsy operands are an empty output, the text {@code false} and an operand that threw an error.</li>
 *     <li>Boolean results (a check tag or a negation) render as nothing, like a boolean in JSX.</li>
 * </ul>
 *
 * Operators are only treated as operators when the element list contains at least one
 * {@code check} tag, so existing payloads containing {@code &&}, {@code ||} or {@code !}
 * keep working unchanged. Operators are parsed as {@link Element.Operator}, a subclass of
 * {@link Element.TextElement}, so every consumer that is unaware of expressions renders
 * them as the literal text they were parsed from.
 */
public final class TagExpressions {

    public static final String CHECK_TAG = "check";

    /**
     * Converts a balanced run of elements into its output. Implemented by the caller so the
     * expression evaluator can reuse the normal conversion pipeline, and so operands are
     * only converted when the expression actually needs their value.
     */
    @FunctionalInterface
    public interface OperandEvaluator {
        String evaluate(List<Element> elements) throws ParseException;
    }

    private TagExpressions() {
    }

    /**
     * Replaces every tag expression in the element list with its rendered output, innermost
     * expression first. Element lists without a check tag are returned untouched.
     */
    public static List<Element> resolve(List<Element> elements, OperandEvaluator evaluator) throws ParseException {
        if (!containsCheckTag(elements)) {
            return elements;
        }
        List<Element> resolved = resolveNestedExpressions(elements, evaluator);
        List<Item> items = tokenise(resolved);
        if (items.stream().noneMatch(Item::isOperator)) {
            return resolved;
        }
        Value value = new ExpressionParser(items, evaluator).parse().evaluate();
        return List.of(new Element.TextElement(value.render()));
    }

    /**
     * Anything other than an empty output or the text "false" is truthy.
     */
    public static boolean isTruthy(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        return !trimmed.isEmpty() && !trimmed.equalsIgnoreCase("false");
    }

    /**
     * True when a check tag appears anywhere in the element list, at any nesting depth.
     */
    private static boolean containsCheckTag(List<Element> elements) {
        for (Element element : elements) {
            if (element instanceof Element.StartTag startTag
                    && CHECK_TAG.equalsIgnoreCase(startTag.getIdentifier())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves the expressions inside the body of every matched tag at this level, so that by
     * the time this level is evaluated its operands no longer contain unevaluated expressions.
     */
    private static List<Element> resolveNestedExpressions(List<Element> elements, OperandEvaluator evaluator)
            throws ParseException {
        List<Element> resolved = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            Element element = elements.get(i);
            int end = isOpenTag(element) ? findMatchingEndTag(elements, i) : -1;
            if (end == -1) {
                resolved.add(element);
                continue;
            }
            resolved.add(element);
            resolved.addAll(resolve(new ArrayList<>(elements.subList(i + 1, end)), evaluator));
            resolved.add(elements.get(end));
            i = end;
        }
        return resolved;
    }

    /**
     * Splits the element list into operands and the operators at this level. Elements inside a
     * matched tag belong to the surrounding operand, so only operators at this level are
     * treated as operators.
     */
    private static List<Item> tokenise(List<Element> elements) {
        List<Item> items = new ArrayList<>();
        List<Element> operand = new ArrayList<>();
        for (int i = 0; i < elements.size(); i++) {
            Element element = elements.get(i);
            int end = isOpenTag(element) ? findMatchingEndTag(elements, i) : -1;
            if (end != -1) {
                operand.addAll(elements.subList(i, end + 1));
                i = end;
                continue;
            }
            if (element instanceof Element.Operator operator) {
                if (operator.getType() == Element.Operator.Type.NOT) {
                    //Negation is only an operator in prefix position, so a trailing or
                    //mid sentence "!" stays literal text.
                    if (isBlank(operand)) {
                        operand.clear();
                        items.add(Item.operator(operator.getType()));
                    } else {
                        operand.add(element);
                    }
                } else {
                    items.add(Item.operand(operand));
                    operand = new ArrayList<>();
                    items.add(Item.operator(operator.getType()));
                }
                continue;
            }
            operand.add(element);
        }
        if (!operand.isEmpty()) {
            items.add(Item.operand(operand));
        }
        return items;
    }

    private static boolean isOpenTag(Element element) {
        return element instanceof Element.StartTag && !(element instanceof Element.SelfClosingTag);
    }

    /**
     * Index of the end tag closing the start tag at {@code start}, or -1 when it is unmatched.
     */
    private static int findMatchingEndTag(List<Element> elements, int start) {
        String identifier = ((Element.StartTag) elements.get(start)).getIdentifier();
        int depth = 0;
        for (int i = start + 1; i < elements.size(); i++) {
            Element element = elements.get(i);
            if (isOpenTag(element) && ((Element.StartTag) element).getIdentifier().equalsIgnoreCase(identifier)) {
                depth++;
            } else if (element instanceof Element.EndTag endTag
                    && endTag.getIdentifier().equalsIgnoreCase(identifier)) {
                if (depth == 0) {
                    return i;
                }
                depth--;
            }
        }
        return -1;
    }

    private static boolean isBlank(List<Element> elements) {
        return elements.stream().allMatch(element -> element instanceof Element.TextElement textElement
                && textElement.getContent().isBlank());
    }

    /**
     * Drops the whitespace surrounding an operand, which is whatever separated it from its operator.
     */
    private static List<Element> trim(List<Element> elements) {
        List<Element> trimmed = new ArrayList<>(elements);
        while (!trimmed.isEmpty() && trimmed.get(0) instanceof Element.TextElement textElement) {
            String content = textElement.getContent().stripLeading();
            if (content.isEmpty()) {
                trimmed.remove(0);
            } else {
                trimmed.set(0, new Element.TextElement(content));
                break;
            }
        }
        while (!trimmed.isEmpty() && trimmed.get(trimmed.size() - 1) instanceof Element.TextElement textElement) {
            String content = textElement.getContent().stripTrailing();
            if (content.isEmpty()) {
                trimmed.remove(trimmed.size() - 1);
            } else {
                trimmed.set(trimmed.size() - 1, new Element.TextElement(content));
                break;
            }
        }
        return trimmed;
    }

    /**
     * True when the operand is nothing but a check tag, whose result is a boolean and therefore
     * renders as nothing.
     */
    private static boolean isBooleanOperand(List<Element> elements) {
        if (elements.isEmpty() || !(elements.get(0) instanceof Element.StartTag startTag)
                || !CHECK_TAG.equalsIgnoreCase(startTag.getIdentifier())) {
            return false;
        }
        if (startTag instanceof Element.SelfClosingTag) {
            return elements.size() == 1;
        }
        return findMatchingEndTag(elements, 0) == elements.size() - 1;
    }

    private static final class Item {
        private final Element.Operator.Type operator;
        private final List<Element> operand;

        private Item(Element.Operator.Type operator, List<Element> operand) {
            this.operator = operator;
            this.operand = operand;
        }

        static Item operator(Element.Operator.Type type) {
            return new Item(type, null);
        }

        static Item operand(List<Element> elements) {
            return new Item(null, elements);
        }

        boolean isOperator() {
            return operator != null;
        }
    }

    @FunctionalInterface
    private interface Node {
        Value evaluate() throws ParseException;
    }

    /**
     * Recursive descent over the operands and operators, building a lazy tree so that
     * evaluation short circuits.
     */
    private static final class ExpressionParser {
        private final List<Item> items;
        private final OperandEvaluator evaluator;
        private int position;

        ExpressionParser(List<Item> items, OperandEvaluator evaluator) {
            this.items = items;
            this.evaluator = evaluator;
        }

        Node parse() {
            return parseOr();
        }

        private Node parseOr() {
            Node left = parseAnd();
            while (peek() == Element.Operator.Type.OR) {
                position++;
                Node right = parseAnd();
                Node current = left;
                left = () -> {
                    Value value = current.evaluate();
                    return value.isTruthy() ? value : right.evaluate();
                };
            }
            return left;
        }

        private Node parseAnd() {
            Node left = parseUnary();
            while (peek() == Element.Operator.Type.AND) {
                position++;
                Node right = parseUnary();
                Node current = left;
                left = () -> {
                    Value value = current.evaluate();
                    return value.isTruthy() ? right.evaluate() : value;
                };
            }
            return left;
        }

        private Node parseUnary() {
            if (peek() == Element.Operator.Type.NOT) {
                position++;
                Node operand = parseUnary();
                return () -> Value.of(!operand.evaluate().isTruthy());
            }
            return parseOperand();
        }

        private Node parseOperand() {
            if (position >= items.size() || items.get(position).isOperator()) {
                return Value::empty;
            }
            List<Element> operand = items.get(position++).operand;
            return () -> evaluateOperand(operand);
        }

        private Value evaluateOperand(List<Element> operand) {
            List<Element> elements = trim(operand);
            if (elements.isEmpty()) {
                return Value.empty();
            }
            String output;
            try {
                output = evaluator.evaluate(elements);
            } catch (ParseException | RuntimeException e) {
                return Value.error(e.getMessage() == null ? e.toString() : e.getMessage());
            }
            return isBooleanOperand(elements) ? Value.of(TagExpressions.isTruthy(output)) : Value.of(output);
        }

        private Element.Operator.Type peek() {
            return position < items.size() ? items.get(position).operator : null;
        }
    }

    /**
     * The result of an operand or of a sub expression. Boolean values render as nothing.
     */
    private static final class Value {
        private final String text;
        private final boolean truthy;
        private final boolean renderable;

        private Value(String text, boolean truthy, boolean renderable) {
            this.text = text;
            this.truthy = truthy;
            this.renderable = renderable;
        }

        static Value of(String text) {
            return new Value(text, TagExpressions.isTruthy(text), true);
        }

        static Value of(boolean truthy) {
            return new Value(Boolean.toString(truthy), truthy, false);
        }

        static Value empty() {
            return new Value("", false, true);
        }

        static Value error(String message) {
            return new Value(message, false, true);
        }

        boolean isTruthy() {
            return truthy;
        }

        String render() {
            return renderable ? text : "";
        }
    }
}
