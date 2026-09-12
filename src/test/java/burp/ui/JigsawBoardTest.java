package burp.ui;

import burp.hv.Hackvertor;
import burp.hv.HackvertorExtension;
import burp.hv.settings.Settings;
import burp.hv.tags.CustomTags;
import burp.hv.tags.Tag;
import burp.hv.ui.jigsaw.JigsawBoard;
import burp.hv.ui.jigsaw.JigsawPiece;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import burp.stubs.StubExtensionHelpers;
import org.assertj.swing.edt.GuiActionRunner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JigsawBoardTest {

    private static Hackvertor hackvertor;

    @BeforeAll
    static void setUp() {
        hackvertor = GuiActionRunner.execute(() -> {
            HackvertorExtension.setHelpers(new StubExtensionHelpers());
            StubCallbacks callbacks = new StubCallbacks(new JFrame("Test"));
            HackvertorExtension.callbacks = callbacks;
            HackvertorExtension.helpers = callbacks.getHelpers();
            HackvertorExtension.stderr = new PrintWriter(callbacks.getStderr(), true);
            HackvertorExtension.stdout = new PrintWriter(callbacks.getStdout(), true);
            HackvertorExtension.tagCodeExecutionKey = CustomTags.generateRandomCodeExecutionKey();
            HackvertorExtension.generalSettings = new Settings("general", callbacks);
            Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
            return new Hackvertor();
        });
    }

    private JigsawBoard board() {
        return GuiActionRunner.execute(() -> {
            JigsawBoard board = new JigsawBoard(hackvertor);
            board.setSize(900, 400);
            return board;
        });
    }

    private void onBoard(Runnable action) {
        GuiActionRunner.execute(() -> {
            action.run();
            return null;
        });
    }

    private String serialize(JigsawBoard board) {
        return GuiActionRunner.execute(board::serialize);
    }

    private void assertRoundTrip(String text) {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText(text));
        assertEquals(text, serialize(board));
    }

    @Test
    public void plainTextRoundTrips() {
        assertRoundTrip("hello world");
    }

    @Test
    public void singleTagRoundTrips() {
        assertRoundTrip("<@base64>hello</@base64>");
    }

    @Test
    public void nestedTagsRoundTrip() {
        assertRoundTrip("<@urlencode><@base64>hello</@base64></@urlencode>");
    }

    @Test
    public void tagWithArgumentsRoundTrips() {
        assertRoundTrip("<@substring(0,5)>hello world</@substring>");
    }

    @Test
    public void selfClosingTagRoundTrips() {
        assertRoundTrip("<@space/>");
    }

    @Test
    public void textAfterTagRoundTrips() {
        assertRoundTrip("<@base64>a</@base64>b");
    }

    @Test
    public void multipleChainsRoundTrip() {
        assertRoundTrip("<@base64>a</@base64><@urlencode>b</@urlencode>");
    }

    @Test
    public void partiallyNestedTagsRoundTrip() {
        assertRoundTrip("<@urlencode>a<@base64>b</@base64></@urlencode>");
    }

    @Test
    public void unclosedTagRoundTrips() {
        assertRoundTrip("<@base64>hello");
    }

    @Test
    public void unknownTagRoundTrips() {
        assertRoundTrip("<@notarealtag>hello</@notarealtag>");
    }

    @Test
    public void emptyTextProducesEmptyBoard() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText(""));
        assertTrue(board.pieces().isEmpty());
        assertEquals("", serialize(board));
    }

    @Test
    public void clickingTagsChainsThemAroundText() {
        JigsawBoard board = board();
        onBoard(() -> {
            board.addTextPiece("hello");
            board.addTagPiece(tag("base64"));
            board.addTagPiece(tag("urlencode"));
        });
        assertEquals("<@urlencode><@base64>hello</@base64></@urlencode>", serialize(board));
    }

    @Test
    public void selfClosingTagIsAppendedToChain() {
        JigsawBoard board = board();
        onBoard(() -> {
            board.addTextPiece("hello");
            board.addTagPiece(tag("space"));
        });
        assertEquals("hello<@space/>", serialize(board));
    }

    @Test
    public void deletingAPieceKeepsTheRestOfTheChain() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@urlencode><@base64>hello</@base64></@urlencode>"));
        JigsawPiece middle = board.pieces().stream()
                .filter(piece -> piece.getPrevious() != null && piece.getNext() != null)
                .findFirst()
                .orElseThrow();
        onBoard(() -> board.deletePiece(middle));
        assertEquals("<@urlencode>hello</@urlencode>", serialize(board));
    }

    @Test
    public void clearingTheBoardEmptiesTheInput() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        onBoard(board::clear);
        assertEquals("", serialize(board));
    }

    @Test
    public void draggingAPieceAwayBreaksTheChain() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(lastPiece(board), 300, 120);
        assertEquals("hello<@base64></@base64>", serialize(board));
    }

    @Test
    public void draggingAPieceBackOntoAChainSnapsItOn() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(lastPiece(board), 300, 120);
        dragPiece(lastPiece(board), -300, -120);
        assertEquals("<@base64>hello</@base64>", serialize(board));
    }

    @Test
    public void tagArgumentsCanBeEditedOnThePiece() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@hex(' ')>foo</@hex>"));
        JTextField separator = argumentFields(lastPiece(board)).get(0);
        assertEquals(" ", separator.getText());
        onBoard(() -> separator.setText("-"));
        assertEquals("<@hex('-')>foo</@hex>", serialize(board));
    }

    @Test
    public void eachTagArgumentGetsItsOwnEditor() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@substring(0,5)>hello world</@substring>"));
        List<JTextField> fields = argumentFields(lastPiece(board));
        assertEquals(2, fields.size());
        onBoard(() -> fields.get(1).setText("3"));
        assertEquals("<@substring(0,3)>hello world</@substring>", serialize(board));
    }

    @Test
    public void booleanArgumentsAreEditedWithAChoice() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@set_variable1(false)>x</@set_variable1>"));
        JComboBox<?> choice = (JComboBox<?>) componentsOfType(lastPiece(board), JComboBox.class).get(0);
        onBoard(() -> choice.setSelectedItem("true"));
        assertEquals("<@set_variable1(true)>x</@set_variable1>", serialize(board));
    }

    @Test
    public void argumentEditorsAreLabelledWithTheParameterName() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@substring(0,5)>hello world</@substring>"));
        List<String> labels = new ArrayList<>();
        for (java.awt.Component component : componentsOfType(lastPiece(board), JLabel.class)) {
            labels.add(((JLabel) component).getText());
        }
        assertTrue(labels.contains("start:"), "expected a start label but had " + labels);
        assertTrue(labels.contains("end:"), "expected an end label but had " + labels);
    }

    @Test
    public void clickingATagWithArgumentsUsesItsDefaults() {
        JigsawBoard board = board();
        onBoard(() -> {
            board.addTextPiece("foo");
            board.addTagPiece(tag("hex"));
        });
        assertEquals("<@hex(' ')>foo</@hex>", serialize(board));
    }

    private List<JTextField> argumentFields(JigsawPiece piece) {
        List<JTextField> fields = new ArrayList<>();
        for (java.awt.Component component : componentsOfType(piece, JTextField.class)) {
            fields.add((JTextField) component);
        }
        return fields;
    }

    private List<java.awt.Component> componentsOfType(JigsawPiece piece, Class<?> type) {
        List<java.awt.Component> matches = new ArrayList<>();
        for (java.awt.Component component : piece.getComponents()) {
            if (type.isInstance(component)) {
                matches.add(component);
            }
        }
        return matches;
    }

    @Test
    public void draggingAPieceOutsideTheInputRemovesIt() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(lastPiece(board), 1200, 0);
        assertEquals(1, board.pieces().size());
        assertEquals("hello", serialize(board));
    }

    @Test
    public void draggingAPieceAboveTheInputRemovesIt() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(lastPiece(board), 0, -200);
        assertEquals("hello", serialize(board));
    }

    @Test
    public void draggingOutsideTheInputRemovesEveryDraggedPiece() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(firstPiece(board), 0, 900);
        assertTrue(board.pieces().isEmpty());
        assertEquals("", serialize(board));
    }

    @Test
    public void draggingInsideTheInputKeepsThePiece() {
        JigsawBoard board = board();
        onBoard(() -> board.loadFromText("<@base64>hello</@base64>"));
        dragPiece(lastPiece(board), 200, 200);
        assertEquals(2, board.pieces().size());
    }

    private JigsawPiece firstPiece(JigsawBoard board) {
        return board.pieces().stream().filter(piece -> piece.getPrevious() == null).findFirst().orElseThrow();
    }

    private JigsawPiece lastPiece(JigsawBoard board) {
        return board.pieces().stream().filter(piece -> piece.getNext() == null).findFirst().orElseThrow();
    }

    private void dragPiece(JigsawPiece piece, int deltaX, int deltaY) {
        onBoard(() -> {
            int pointerX = piece.getX() + 5 + deltaX;
            int pointerY = piece.getY() + 5 + deltaY;
            dispatch(piece, MouseEvent.MOUSE_PRESSED, 5, 5);
            dispatch(piece, MouseEvent.MOUSE_DRAGGED, 5 + deltaX, 5 + deltaY);
            dispatch(piece, MouseEvent.MOUSE_RELEASED, pointerX - piece.getX(), pointerY - piece.getY());
        });
    }

    private void dispatch(JigsawPiece piece, int id, int x, int y) {
        MouseEvent event = new MouseEvent(piece, id, System.currentTimeMillis(), 0, x, y, 1, false);
        for (MouseListener listener : piece.getMouseListeners()) {
            if (id == MouseEvent.MOUSE_PRESSED) {
                listener.mousePressed(event);
            } else if (id == MouseEvent.MOUSE_RELEASED) {
                listener.mouseReleased(event);
            }
        }
        if (id == MouseEvent.MOUSE_DRAGGED) {
            for (MouseMotionListener listener : piece.getMouseMotionListeners()) {
                listener.mouseDragged(event);
            }
        }
    }

    private Tag tag(String name) {
        return TagUtils.getTagByTagName(hackvertor.getTags(), name);
    }
}
