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

public class JigsawTagPiece extends JigsawPiece {

    private static final int MIN_ARGUMENT_COLUMNS = 3;
    private static final int MAX_ARGUMENT_COLUMNS = 24;

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
        addArgumentEditor(tag.argument1, argumentAt(arguments, 0));
        addArgumentEditor(tag.argument2, argumentAt(arguments, 1));
        addArgumentEditor(tag.argument3, argumentAt(arguments, 2));
        addArgumentEditor(tag.argument4, argumentAt(arguments, 3));
        setToolTipText(tag.tooltip);
        setSize(getPreferredSize());
    }

    private String argumentAt(List<String> arguments, int index) {
        if (arguments == null || index >= arguments.size()) {
            return null;
        }
        return arguments.get(index);
    }

    private void addArgumentEditor(TagArgument argument, String value) {
        if (argument == null) {
            return;
        }
        String initial = value != null ? value : argument.value;
        if ("boolean".equalsIgnoreCase(argument.type)) {
            JComboBox<String> choice = new JComboBox<>(new String[]{"true", "false"});
            choice.setSelectedItem("false".equalsIgnoreCase(initial) ? "false" : "true");
            choice.addActionListener(event -> board.pieceEdited(this));
            argumentEditors.add(choice);
            add(choice);
            return;
        }
        JTextField field = new JTextField(initial, columnsFor(initial));
        field.setForeground(JigsawColours.TEXT);
        field.setBackground(JigsawColours.EDITOR_BACKGROUND);
        field.setCaretColor(JigsawColours.TEXT);
        field.setToolTipText(argument.type);
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
