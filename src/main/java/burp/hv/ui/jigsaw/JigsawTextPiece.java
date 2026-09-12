package burp.hv.ui.jigsaw;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

public class JigsawTextPiece extends JigsawPiece {

    private static final int MIN_COLUMNS = 6;
    private static final int MAX_COLUMNS = 60;
    private static final int MAX_ROWS = 8;

    private final JTextArea editor = new JTextArea();

    public JigsawTextPiece(JigsawBoard board, String text) {
        super(board);
        JLabel grip = new JLabel("text");
        grip.setForeground(JigsawColours.TEXT);
        grip.setFont(grip.getFont().deriveFont(Font.BOLD));
        grip.setToolTipText("Drag to move this piece");
        makeDraggable(grip);
        add(grip);
        editor.setText(text);
        editor.setForeground(JigsawColours.TEXT);
        editor.setBackground(JigsawColours.EDITOR_BACKGROUND);
        editor.setCaretColor(JigsawColours.TEXT);
        editor.setBorder(new LineBorder(JigsawColours.TEXT_PIECE.darker()));
        editor.setFont(new Font(Font.MONOSPACED, Font.PLAIN, grip.getFont().getSize()));
        editor.setTabSize(4);
        resizeEditor();
        editor.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent event) {
                textChanged();
            }

            public void removeUpdate(DocumentEvent event) {
                textChanged();
            }

            public void changedUpdate(DocumentEvent event) {
                textChanged();
            }
        });
        add(editor);
        setSize(getPreferredSize());
    }

    private void textChanged() {
        SwingUtilities.invokeLater(() -> {
            resizeEditor();
            board.pieceEdited(this);
        });
    }

    private void resizeEditor() {
        String[] lines = editor.getText().split("\n", -1);
        int longest = 0;
        for (String line : lines) {
            longest = Math.max(longest, line.length());
        }
        editor.setColumns(Math.min(MAX_COLUMNS, Math.max(MIN_COLUMNS, longest + 1)));
        editor.setRows(Math.min(MAX_ROWS, Math.max(1, lines.length)));
    }

    public void focusEditor() {
        editor.requestFocusInWindow();
        editor.setCaretPosition(editor.getDocument().getLength());
    }

    public String getText() {
        return editor.getText();
    }

    @Override
    public String wrap(String accumulated) {
        return accumulated + editor.getText();
    }

    @Override
    protected Color fillColour() {
        return JigsawColours.TEXT_PIECE;
    }
}
