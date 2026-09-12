package burp.hv.ui.jigsaw;

import burp.hv.tags.Tag;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.List;

class JigsawTextParser {

    private final JigsawBoard board;
    private final Collection<Tag> tags;

    JigsawTextParser(JigsawBoard board, Collection<Tag> tags) {
        this.board = board;
        this.tags = tags;
    }

    private static class Node {
        private String text;
        private String identifier;
        private ArrayList<String> arguments;
        private boolean selfClosing;
        private boolean closed;
        private final List<Node> children = new ArrayList<>();

        private boolean isText() {
            return text != null;
        }

        private String raw() {
            if (isText()) {
                return text;
            }
            if (selfClosing) {
                return new Element.SelfClosingTag(identifier, arguments).toString();
            }
            StringBuilder builder = new StringBuilder();
            builder.append(new Element.StartTag(identifier, arguments));
            for (Node child : children) {
                builder.append(child.raw());
            }
            if (closed) {
                builder.append(new Element.EndTag(identifier));
            }
            return builder.toString();
        }
    }

    List<List<JigsawPiece>> chainsFor(String text) {
        if (text == null || text.isEmpty()) {
            return new ArrayList<>();
        }
        List<Node> nodes;
        try {
            nodes = buildNodes(HackvertorParser.parse(text));
        } catch (ParseException e) {
            Node fallback = new Node();
            fallback.text = text;
            nodes = List.of(fallback);
        }
        return splitIntoChains(nodes);
    }

    private List<Node> buildNodes(List<Element> elements) {
        List<Node> roots = new ArrayList<>();
        Deque<Node> open = new ArrayDeque<>();
        for (Element element : elements) {
            List<Node> target = open.isEmpty() ? roots : open.peek().children;
            if (element instanceof Element.SelfClosingTag) {
                target.add(tagNode((Element.StartTag) element, true));
            } else if (element instanceof Element.StartTag) {
                Node node = tagNode((Element.StartTag) element, false);
                target.add(node);
                open.push(node);
            } else if (element instanceof Element.EndTag) {
                Node match = findOpenTag(open, ((Element.EndTag) element).getIdentifier());
                if (match == null) {
                    appendText(target, element.toString());
                } else {
                    while (open.peek() != match) {
                        open.pop();
                    }
                    open.pop();
                    match.closed = true;
                }
            } else {
                appendText(target, element.toString());
            }
        }
        return roots;
    }

    private Node tagNode(Element.StartTag element, boolean selfClosing) {
        Node node = new Node();
        node.identifier = element.getIdentifier();
        node.arguments = element.getArguments();
        node.selfClosing = selfClosing;
        node.closed = selfClosing;
        return node;
    }

    private Node findOpenTag(Deque<Node> open, String identifier) {
        for (Node node : open) {
            if (node.identifier.equalsIgnoreCase(identifier)) {
                return node;
            }
        }
        return null;
    }

    private void appendText(List<Node> target, String text) {
        if (!target.isEmpty() && target.get(target.size() - 1).isText()) {
            Node last = target.get(target.size() - 1);
            last.text = last.text + text;
            return;
        }
        Node node = new Node();
        node.text = text;
        target.add(node);
    }

    private List<List<JigsawPiece>> splitIntoChains(List<Node> nodes) {
        List<List<JigsawPiece>> chains = new ArrayList<>();
        List<JigsawPiece> current = new ArrayList<>();
        for (Node node : nodes) {
            Tag tag = node.isText() ? null : findTag(node.identifier);
            boolean wrapsContent = tag != null && node.closed && !node.selfClosing;
            if (wrapsContent && !current.isEmpty()) {
                chains.add(current);
                current = new ArrayList<>();
            }
            current.addAll(piecesFor(node, tag));
        }
        if (!current.isEmpty()) {
            chains.add(current);
        }
        return chains;
    }

    private List<JigsawPiece> toChain(List<Node> nodes) {
        List<JigsawPiece> chain = new ArrayList<>();
        for (Node node : nodes) {
            Tag tag = node.isText() ? null : findTag(node.identifier);
            boolean wrapsContent = tag != null && node.closed && !node.selfClosing;
            if (wrapsContent && !chain.isEmpty()) {
                chain.add(new JigsawTextPiece(board, node.raw()));
                continue;
            }
            chain.addAll(piecesFor(node, tag));
        }
        return chain;
    }

    private Tag findTag(String identifier) {
        for (Tag tag : tags) {
            if (tag.name.equalsIgnoreCase(identifier)) {
                return tag;
            }
        }
        return null;
    }

    private List<JigsawPiece> piecesFor(Node node, Tag tag) {
        if (node.isText()) {
            return List.of(new JigsawTextPiece(board, node.text));
        }
        if (tag == null || !node.closed) {
            return List.of(new JigsawTextPiece(board, node.raw()));
        }
        if (node.selfClosing) {
            return List.of(new JigsawTagPiece(board, tag, node.arguments, true));
        }
        List<JigsawPiece> pieces = new ArrayList<>(toChain(node.children));
        pieces.add(new JigsawTagPiece(board, tag, node.arguments, false));
        return pieces;
    }
}
