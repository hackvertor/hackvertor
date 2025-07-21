package burp.ui;

import burp.hv.HackvertorExtension;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.FailOnThreadViolationRepaintManager;
import org.assertj.swing.edt.GuiActionRunner;
import org.assertj.swing.fixture.FrameFixture;
import org.junit.jupiter.api.*;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class HackvertorUiTest {

    private FrameFixture window;
    private JFrame frame;

    @BeforeAll
    static void installRepaintManager() {
        FailOnThreadViolationRepaintManager.install(); // Ensures all UI access is EDT-safe
    }

    @BeforeEach
    void setUp() {
        SwingUtilities.invokeLater(() -> {
            frame = new JFrame("Burp Suite - Hackvertor");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setContentPane(new JPanel(new BorderLayout()));
            frame.setPreferredSize(new Dimension(1200, 1000));
            JMenuBar menuBar = new JMenuBar();
            frame.setJMenuBar(menuBar);

            HackvertorExtension hackvertorExtension = new HackvertorExtension();
            hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(frame));

            frame.pack();
            frame.setVisible(true);
        });

        // Wait until frame is ready before wrapping
        try {
            Thread.sleep(200); // small delay to allow EDT to show the frame
        } catch (InterruptedException ignored) {}

        window = new FrameFixture(frame);
        window.show(); // ensures AssertJ knows it’s visible
    }

    @Test
    void testWindowTitleAndSize() {
        window.requireVisible();
        window.requireTitle("Burp Suite - Hackvertor");
        Assertions.assertEquals(1200, window.target().getWidth());
        Assertions.assertEquals(1000, window.target().getHeight());
    }

    @Test
    void testClickBase64Button() throws Exception {
        // Wait for UI to be ready
        window.robot().waitForIdle();
        
        // First, focus on the first HackvertorInput (input area) to ensure cursor is there
        Component[] allTextAreas = window.robot().finder()
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea inputArea = null;
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                inputArea = (JTextArea) component;
                break; // Get the first HackvertorInput (which should be the input area)
            }
        }
        
        if (inputArea != null) {
            // Click on the input area to give it focus
            window.robot().click(inputArea);
            window.robot().waitForIdle();
        }
        
        // Find all tab panes
        List<JTabbedPane> tabPanes = window.robot().finder().findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        // Get the inner tabs (tag categories)
        JTabbedPane innerTabs = tabPanes.get(0);
        
        // The Encode tab should already be selected by default
        // No need to switch tabs as per HackvertorPanel.buildTabbedPane() line 565:
        // tabs.setSelectedIndex(tabs.indexOfTab("Encode"));
        
        // Get the selected tab content (should be Encode tab now)
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find the base64 button
        Component base64Button = window.robot().finder().find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "base64".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );

        // Click the button using different approaches
        JButton button = (JButton) base64Button;
        
        // Try clicking using GuiActionRunner to ensure it runs on EDT
        GuiActionRunner.execute(() -> button.doClick());

        // Give the UI time to update
        window.robot().waitForIdle();
        Thread.sleep(500);
        
        // Check all JTextAreas to see if the base64 tag has been added
        Component[] components = window.robot().finder()
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        boolean foundBase64Tag = false;
        for (Component component : components) {
            JTextArea textArea = (JTextArea) component;
            String text = textArea.getText();
            
            // Check for the base64 tags
            if (text.contains("<@base64>") && text.contains("</@base64>")) {
                foundBase64Tag = true;
                break;
            }
        }
        
        Assertions.assertTrue(foundBase64Tag, "base64 tag should be added to a JTextArea after clicking the button");
    }

    @Test
    void testBase64EncodingWithText() throws Exception {
        // Wait for UI to be ready
        window.robot().waitForIdle();
        Thread.sleep(500);
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window.robot().finder()
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea inputArea = null;
        JTextArea outputArea = null;
        int hackvertorInputCount = 0;
        
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                if (hackvertorInputCount == 0) {
                    inputArea = (JTextArea) component;
                } else if (hackvertorInputCount == 1) {
                    outputArea = (JTextArea) component;
                }
                hackvertorInputCount++;
            }
        }
        
        Assertions.assertNotNull(inputArea, "Input area should be found");
        Assertions.assertNotNull(outputArea, "Output area should be found");
        
        // Type "test" in the input area
        window.robot().click(inputArea);
        window.robot().waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.robot().waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(() -> finalInputArea.selectAll());
        window.robot().waitForIdle();
        
        // Find the tabbed pane and base64 button
        List<JTabbedPane> tabPanes = window.robot().finder().findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find and click the base64 button
        Component base64Button = window.robot().finder().find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "base64".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) base64Button;
        GuiActionRunner.execute(() -> button.doClick());
        
        // Wait for processing
        window.robot().waitForIdle();
        Thread.sleep(1000); // Give time for conversion to happen
        
        // Check that input area contains the tags around "test"
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@base64>test</@base64>", inputText, "Input should have base64 tags around 'test'");
        
        // Check that output area contains the base64 encoded value of "test"
        String outputText = outputArea.getText();
        Assertions.assertEquals("dGVzdA==", outputText, "Output should contain base64 encoded 'test'");
    }

    @AfterEach
    void tearDown() {
        if (window != null) {
            window.cleanUp();
        }
    }
}
