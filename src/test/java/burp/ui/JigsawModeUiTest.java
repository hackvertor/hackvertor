package burp.ui;

import burp.hv.HackvertorExtension;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.GuiActionRunner;
import org.assertj.swing.fixture.FrameFixture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;

public class JigsawModeUiTest {

    private static FrameFixture window;
    private static JFrame frame;

    @BeforeAll
    static void setUp() {
        System.setProperty("java.awt.headless", "false");
        SwingUtilities.invokeLater(() -> {
            frame = new JFrame("Burp Suite - Hackvertor");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setContentPane(new JPanel(new BorderLayout()));
            frame.setPreferredSize(new Dimension(1200, 1000));
            frame.setJMenuBar(new JMenuBar());
            HackvertorExtension hackvertorExtension = new HackvertorExtension();
            hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(frame));
            frame.pack();
            frame.setVisible(true);
        });
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {
        }
        window = new FrameFixture(frame);
        window.show();
    }

    @AfterAll
    static void tearDown() {
        window.cleanUp();
    }

    @Test
    void tagModeSplitsInputAndOutputEvenly() {
        UiTestSupport.selectInputMode(window, UiTestSupport.TAG_MODE);
        window.robot().waitForIdle();
        int difference = Math.abs(inputPaneWidth() - outputPaneWidth());
        Assertions.assertTrue(difference <= 2,
                "tag mode should split evenly but input was " + inputPaneWidth() + " and output " + outputPaneWidth());
    }

    @Test
    void jigsawModeGivesTheCanvasMoreRoomThanTheOutput() {
        UiTestSupport.selectInputMode(window, UiTestSupport.JIGSAW_MODE);
        window.robot().waitForIdle();
        Assertions.assertTrue(inputPaneWidth() > outputPaneWidth(),
                "jigsaw canvas should be wider but input was " + inputPaneWidth() + " and output " + outputPaneWidth());
    }

    @Test
    void textPieceAndTagPieceProduceTagsAndOutput() throws Exception {
        UiTestSupport.selectInputMode(window, UiTestSupport.JIGSAW_MODE);
        clearBoard();
        addTextPiece("test");
        clickTagButton("base64");
        window.robot().waitForIdle();
        Thread.sleep(400);
        Assertions.assertEquals("<@base64>test</@base64>", GuiActionRunner.execute(() -> inputArea().getText()));
        Assertions.assertEquals("dGVzdA==", GuiActionRunner.execute(() -> outputArea().getText()));
    }

    @Test
    void switchingToTagModeKeepsTheGeneratedTags() throws Exception {
        UiTestSupport.selectInputMode(window, UiTestSupport.JIGSAW_MODE);
        clearBoard();
        addTextPiece("test");
        clickTagButton("base64");
        window.robot().waitForIdle();
        Thread.sleep(400);
        UiTestSupport.selectInputMode(window, UiTestSupport.TAG_MODE);
        Assertions.assertTrue(inputArea().isShowing(), "Tag mode input should be visible in tag mode");
        Assertions.assertEquals("<@base64>test</@base64>", GuiActionRunner.execute(() -> inputArea().getText()));
        UiTestSupport.selectInputMode(window, UiTestSupport.JIGSAW_MODE);
        Assertions.assertEquals(2, jigsawPieces().length, "Tags should be rebuilt as jigsaw pieces");
    }

    private int inputPaneWidth() {
        return GuiActionRunner.execute(() ->
                SwingUtilities.getAncestorOfClass(JScrollPane.class, inputArea()).getParent().getWidth());
    }

    private int outputPaneWidth() {
        return GuiActionRunner.execute(() ->
                SwingUtilities.getAncestorOfClass(JScrollPane.class, outputArea()).getWidth());
    }

    private void clearBoard() {
        clickButton("Clear board");
        window.robot().waitForIdle();
    }

    private void addTextPiece(String text) {
        clickButton("+Text");
        window.robot().waitForIdle();
        JTextArea editor = (JTextArea) window.robot().finder().find(window.target(),
                component -> component instanceof JTextArea
                        && component.getParent() != null
                        && component.getParent().getClass().getName().endsWith("JigsawTextPiece"));
        GuiActionRunner.execute(() -> editor.setText(text));
        window.robot().waitForIdle();
    }

    private void clickButton(String label) {
        JButton button = (JButton) window.robot().finder().find(window.target(),
                component -> component instanceof JButton && label.equals(((JButton) component).getText()));
        GuiActionRunner.execute(() -> button.doClick());
    }

    private void clickTagButton(String tagName) {
        JTabbedPane tabs = (JTabbedPane) window.robot().finder().findAll(
                component -> component instanceof JTabbedPane && component.isShowing()).iterator().next();
        Component category = GuiActionRunner.execute(tabs::getSelectedComponent);
        JButton button = (JButton) window.robot().finder().find((Container) category,
                component -> component instanceof JButton && tagName.equals(((JButton) component).getText()));
        GuiActionRunner.execute(() -> button.doClick());
    }

    private Component[] jigsawPieces() {
        return window.robot().finder().findAll(window.target(),
                component -> component.getClass().getName().startsWith("burp.hv.ui.jigsaw.Jigsaw")
                        && component.getClass().getName().endsWith("Piece")).toArray(new Component[0]);
    }

    private JComboBox<?> inputModeSelector() {
        return (JComboBox<?>) window.robot().finder().find(window.target(),
                component -> component instanceof JComboBox && "inputModeSelector".equals(component.getName()));
    }

    private JTextArea inputArea() {
        return hackvertorInput(0);
    }

    private JTextArea outputArea() {
        return hackvertorInput(1);
    }

    private JTextArea hackvertorInput(int index) {
        Component[] areas = window.robot().finder().findAll(window.target(),
                component -> component.getClass().getName().equals("burp.hv.ui.HackvertorInput")).toArray(new Component[0]);
        return (JTextArea) areas[index];
    }
}
