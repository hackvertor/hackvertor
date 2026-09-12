package burp.hv.ui.jigsaw;

import burp.hv.tags.Tag;
import burp.hv.tags.TagArgument;
import burp.parser.Element;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JigsawTagPiece extends JigsawPiece {

    private static final int MIN_ARGUMENT_COLUMNS = 4;
    private static final int MAX_ARGUMENT_COLUMNS = 24;
    private static final Pattern SIGNATURE = Pattern.compile("^[\\w$]+\\((.*)\\)$");

    private final Tag tag;
    private final boolean selfClosing;
    private final List<JComponent> argumentEditors = new ArrayList<>();

    public JigsawTagPiece(JigsawBoard board, Tag tag, List<String> arguments) {
        super(board);
        this.tag = tag;
        this.selfClosing = !tag.hasInput;
        buildContents(arguments);
    }

    public JigsawTagPiece(JigsawBoard board, Tag tag, List<String> arguments, boolean selfClosing) {
        super(board);
        this.tag = tag;
        this.selfClosing = selfClosing;
        buildContents(arguments);
    }

    private void buildContents(List<String> arguments) {
        JLabel name = new JLabel(tag.name);
        name.setForeground(JigsawColours.TEXT);
        name.setFont(name.getFont().deriveFont(Font.BOLD));
        name.setToolTipText(tag.tooltip);
        makeDraggable(name);
        add(name);
        List<TagArgument> declared = declaredArguments();
        List<String> names = parameterNames(declared.size());
        for (int index = 0; index < declared.size(); index++) {
            addArgumentEditor(declared.get(index), argumentAt(arguments, index),
                    index < names.size() ? names.get(index) : null);
        }
        setToolTipText(tag.tooltip);
        setSize(getPreferredSize());
    }

    private List<TagArgument> declaredArguments() {
        List<TagArgument> declared = new ArrayList<>();
        for (TagArgument argument : new TagArgument[]{tag.argument1, tag.argument2, tag.argument3, tag.argument4}) {
            if (argument != null) {
                declared.add(argument);
            }
        }
        return declared;
    }

    private List<String> parameterNames(int argumentCount) {
        List<String> names = new ArrayList<>();
        if (argumentCount == 0 || tag.tooltip == null) {
            return names;
        }
        String tooltip = tag.tooltip;
        int comment = tooltip.indexOf("//");
        if (comment > -1) {
            tooltip = tooltip.substring(0, comment);
        }
        Matcher signature = SIGNATURE.matcher(tooltip.trim());
        if (!signature.matches() || signature.group(1).isBlank()) {
            return names;
        }
        for (String parameter : signature.group(1).split(",")) {
            String[] words = parameter.trim().split("\\s+");
            names.add(words[words.length - 1]);
        }
        if (names.size() == argumentCount + 1) {
            names.remove(0);
        }
        return names.size() == argumentCount ? names : new ArrayList<>();
    }

    private String argumentAt(List<String> arguments, int index) {
        if (arguments == null || index >= arguments.size()) {
            return null;
        }
        return arguments.get(index);
    }

    private void addArgumentEditor(TagArgument argument, String value, String name) {
        if (argument == null) {
            return;
        }
        String initial = value != null ? value : argument.value;
        String description = name != null ? name + " (" + argument.type + ")" : argument.type;
        if (name != null) {
            JLabel label = new JLabel(name + ":");
            label.setForeground(JigsawColours.PARAMETER_NAME);
            label.setFont(label.getFont().deriveFont(Font.PLAIN, label.getFont().getSize() - 1f));
            label.setToolTipText(description);
            makeDraggable(label);
            add(label);
        }
        if ("boolean".equalsIgnoreCase(argument.type)) {
            JComboBox<String> choice = new JComboBox<>(new String[]{"true", "false"});
            choice.setSelectedItem("false".equalsIgnoreCase(initial) ? "false" : "true");
            choice.setToolTipText(description);
            choice.addActionListener(event -> board.pieceEdited(this));
            argumentEditors.add(choice);
            add(choice);
            return;
        }
        JTextField field = new JTextField(initial, columnsFor(initial));
        field.setForeground(JigsawColours.TEXT);
        field.setBackground(JigsawColours.EDITOR_BACKGROUND);
        field.setCaretColor(JigsawColours.TEXT);
        field.setToolTipText(description);
        field.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent event) {
                argumentChanged(field);
            }

            public void removeUpdate(DocumentEvent event) {
                argumentChanged(field);
            }

            public void changedUpdate(DocumentEvent event) {
                argumentChanged(field);
            }
        });
        argumentEditors.add(field);
        add(field);
    }

    private void argumentChanged(JTextField field) {
        SwingUtilities.invokeLater(() -> {
            field.setColumns(columnsFor(field.getText()));
            board.pieceEdited(this);
        });
    }

    private int columnsFor(String value) {
        int length = value == null ? 0 : value.length();
        return Math.min(MAX_ARGUMENT_COLUMNS, Math.max(MIN_ARGUMENT_COLUMNS, length + 1));
    }

    public Tag getTag() {
        return tag;
    }

    private ArrayList<String> currentArguments() {
        ArrayList<String> arguments = new ArrayList<>();
        for (JComponent editor : argumentEditors) {
            if (editor instanceof JComboBox) {
                arguments.add(String.valueOf(((JComboBox<?>) editor).getSelectedItem()));
            } else {
                arguments.add(((JTextField) editor).getText());
            }
        }
        return arguments;
    }

    @Override
    public String wrap(String accumulated) {
        ArrayList<String> arguments = currentArguments();
        if (selfClosing) {
            return accumulated + new Element.SelfClosingTag(tag.name, arguments);
        }
        return new Element.StartTag(tag.name, arguments) + accumulated + new Element.EndTag(tag.name);
    }

    @Override
    protected Color fillColour() {
        return JigsawColours.forCategory(tag.category);
    }
}
