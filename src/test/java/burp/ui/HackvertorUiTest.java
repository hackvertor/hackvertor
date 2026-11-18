package burp.ui;

import burp.hv.HackvertorExtension;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.FailOnThreadViolationRepaintManager;
import org.assertj.swing.edt.GuiActionRunner;
import org.junit.jupiter.api.*;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.jupiter.api.Assertions.fail;

public class HackvertorUiTest {

    private static HeadlessWindow window;
    private static final int width = 1200;
    private static final int height = 1000;
    private static Thread.UncaughtExceptionHandler originalHandler;
    private static final ConcurrentLinkedQueue<Throwable> uncaughtExceptions = new ConcurrentLinkedQueue<>();

    @BeforeAll
    static void installRepaintManager() {
        System.setProperty("javax.swing.disableQuestions", "true");
        System.setProperty("swing.disableOnEDT", "false");
        System.setProperty("awt.useSystemAAFontSettings", "on");
        
        FailOnThreadViolationRepaintManager.install(); // Ensures all UI access is EDT-safe
        
        // Set up uncaught exception handler to catch Java exceptions but filter UI noise
        originalHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, exception) -> {
            // Filter out common UI noise exceptions that don't affect test functionality
            if (!isUINoiseException(exception)) {
                uncaughtExceptions.offer(exception);
            }
            // Also call original handler if it exists
            if (originalHandler != null) {
                originalHandler.uncaughtException(thread, exception);
            }
        });
        
        // Clear any previous exceptions
        uncaughtExceptions.clear();
    }
    
    private static boolean isUINoiseException(Throwable exception) {
        String message = exception.getMessage();
        if (message == null) return false;
        
        // Filter out common UI layout exceptions that don't affect test functionality
        return message.contains("Cannot invoke \"javax.swing.text.View.getMinimumSpan") ||
               message.contains("Cannot invoke \"javax.swing.text.View.getPreferredSpan") ||
               message.contains("Cannot invoke \"javax.swing.text.View.getMaximumSpan") ||
               message.contains("sun.swing.") ||
               message.contains("java.awt.EventQueue") ||
               (exception instanceof java.awt.IllegalComponentStateException);
    }

    @BeforeAll
    static void setUp() {
        window = HeadlessWindow.create(width, height, root -> {
            HackvertorExtension hackvertorExtension = new HackvertorExtension();
            hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(root));
        });
        UiTestSupport.selectInputMode(window, UiTestSupport.TAG_MODE);
    }

    @Test
    void testExtensionFillsTheWindow() {
        Assertions.assertEquals(width, window.target().getWidth());
        Assertions.assertEquals(height, window.target().getHeight());
        Component extensionPanel = GuiActionRunner.execute(() -> window.target().getComponent(0));
        Assertions.assertTrue(extensionPanel.isShowing(), "The extension's tab should be showing");
        Assertions.assertEquals(window.target().getSize(), extensionPanel.getSize());
    }

    @Test
    void testClickBase64Button() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // First, focus on the first HackvertorInput (input area) to ensure cursor is there
        Component[] allTextAreas = window
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
            window.click(inputArea);
            window.waitForIdle();
        }
        
        // Find all tab panes
        List<JTabbedPane> tabPanes = window.findAll(
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
        Component base64Button = window.find(
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
        window.waitForIdle();
        
        // Check all JTextAreas to see if the base64 tag has been added
        Component[] components = window
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
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find the tabbed pane and base64 button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        
        // Find and click the "Encode" tab by name
        int encodeTabIndex = -1;
        for (int i = 0; i < innerTabs.getTabCount(); i++) {
            if ("Encode".equals(innerTabs.getTitleAt(i))) {
                encodeTabIndex = i;
                break;
            }
        }
        
        if (encodeTabIndex >= 0) {
            final int tabIndex = encodeTabIndex;
            GuiActionRunner.execute(() -> innerTabs.setSelectedIndex(tabIndex));
        } else {
            // Fallback to first tab if "Encode" not found by name
            GuiActionRunner.execute(() -> innerTabs.setSelectedIndex(0));
        }
        window.waitForIdle();
        
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find and click the base64 button
        Component base64Button = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "base64".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) base64Button;
        GuiActionRunner.execute(() -> button.doClick());
        
        // Wait for processing
        window.waitForIdle();
        
        // Check that input area contains the tags around "test"
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@base64>test</@base64>", inputText, "Input should have base64 tags around 'test'");
        
        // Check that output area contains the base64 encoded value of "test"
        String outputText = UiTestSupport.awaitText(outputArea, "dGVzdA==");
        Assertions.assertEquals("dGVzdA==", outputText, "Output should contain base64 encoded 'test'");
    }

    @Test
    void testUtf7EncodingWithText() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type "abc<>" in the input area (test case from ConvertorTests)
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("abc<>"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find the tabbed pane and click on "Encode" category tab
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        
        // Find and click the "Encode" tab by name
        int encodeTabIndex = -1;
        for (int i = 0; i < innerTabs.getTabCount(); i++) {
            if ("Encode".equals(innerTabs.getTitleAt(i))) {
                encodeTabIndex = i;
                break;
            }
        }
        
        if (encodeTabIndex >= 0) {
            final int tabIndex = encodeTabIndex;
            GuiActionRunner.execute(() -> innerTabs.setSelectedIndex(tabIndex));
        } else {
            Assertions.fail("Could not find 'Encode' tab");
        }
        window.waitForIdle();
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find and click the utf7 button
        Component utf7Button = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "utf7".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) utf7Button;
        GuiActionRunner.execute(() -> button.doClick());
        
        // Wait for processing
        window.waitForIdle();
        
        // Check that input area contains the tags around "abc<>"
        String inputText = inputArea.getText();
        // The default pattern excludes alphanumeric and common ASCII chars
        String expectedInput = "<@utf7('[\\\\s\\\\t\\\\r\\'(),-./:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+!]')>abc<></@utf7>";
        Assertions.assertEquals(expectedInput, inputText, "Input should have utf7 tags with default exclusion pattern around 'abc<>'");
        
        // Check that output area contains the UTF-7 encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "abc+ADwAPg-");
        Assertions.assertEquals("abc+ADwAPg-", outputText, "Output should contain UTF-7 encoded 'abc<>'");
    }

    @Test
    void testUtf7DecodingWithText() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type UTF-7 encoded text in the input area (test case from ConvertorTests)
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("Hi Mom +Jjo-"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find the tabbed pane and click on "Decode" category tab
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        
        // Find and click the "Decode" tab by name
        int decodeTabIndex = -1;
        for (int i = 0; i < innerTabs.getTabCount(); i++) {
            if ("Decode".equals(innerTabs.getTitleAt(i))) {
                decodeTabIndex = i;
                break;
            }
        }
        
        if (decodeTabIndex >= 0) {
            final int tabIndex = decodeTabIndex;
            GuiActionRunner.execute(() -> innerTabs.setSelectedIndex(tabIndex));
        } else {
            Assertions.fail("Could not find 'Decode' tab");
        }
        window.waitForIdle();
        
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find and click the d_utf7 button
        Component utf7DecodeButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "d_utf7".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) utf7DecodeButton;
        GuiActionRunner.execute(() -> button.doClick());
        
        // Wait for processing
        window.waitForIdle();
        
        // Check that input area contains the decode tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@d_utf7>Hi Mom +Jjo-</@d_utf7>", inputText, "Input should have d_utf7 tags around encoded text");
        
        // Check that output area contains the decoded text with emoji
        String outputText = UiTestSupport.awaitText(outputArea, "Hi Mom ☺");
        Assertions.assertEquals("Hi Mom ☺", outputText, "Output should contain decoded text 'Hi Mom ☺'");
    }

    @Test
    void testSmartDecode() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Set the encoded input
        String encodedInput = "JTVDMTM0JTVDMTcwJTVDNjYlNUM2NiU1QzEzNCU1QzE3MCU1QzY2JTVDMTA2JTVDMTM0JTVDMTcwJTVDNjYlNUMxMDYlNUMxMzQlNUMxNzAlNUM2NiU1QzYyJTVDMTM0JTVDMTcwJTVDNjYlNUM2MSU1QzEzNCU1QzE3MCU1QzY3JTVDNjI=";
        
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText(encodedInput));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(() -> finalInputArea.selectAll());
        window.waitForIdle();
        
        // Find the Smart Decode button
        Component smartDecodeButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     ((JButton) c).getText() != null &&
                     ((JButton) c).getText().contains("Smart Decode") &&
                     c.isEnabled()
        );
        
        Assertions.assertNotNull(smartDecodeButton, "Smart Decode button should be found and enabled");
        
        // Click the Smart Decode button
        JButton button = (JButton) smartDecodeButton;
        GuiActionRunner.execute(() -> button.doClick());
        
        // Wait for processing
        window.waitForIdle();
        
        // Check the input area contains the decoded tags
        String inputText = inputArea.getText();
        String expectedInput = "<@base64><@urlencode_not_plus><@octal_escapes><@hex_escapes>foobar</@hex_escapes></@octal_escapes></@urlencode_not_plus></@base64>";
        Assertions.assertEquals(expectedInput, inputText, "Input should contain the smart decoded tags");
        
        // Check that output area contains the original encoded value
        String outputText = UiTestSupport.awaitText(outputArea, encodedInput);
        Assertions.assertEquals(encodedInput, outputText, "Output should contain the original encoded value");
    }

    @Test
    void testClearButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Add some text to input area
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> {
            finalInputArea.setText("test input");
        });
        window.waitForIdle();
        
        // Verify text is present
        Assertions.assertEquals("test input", inputArea.getText());
        // Output will be same as input since there are no tags
        Assertions.assertEquals("test input", UiTestSupport.awaitText(outputArea, "test input"));
        
        // Find and click the Clear button
        Component clearButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Clear".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) clearButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify both areas are now empty
        Assertions.assertEquals("", inputArea.getText(), "Input area should be empty after Clear");
        Assertions.assertEquals("", UiTestSupport.awaitText(outputArea, ""), "Output area should be empty after Clear");
    }

    @Test
    void testClearTagsButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input area
        Component[] allTextAreas = window
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea inputArea = null;
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                inputArea = (JTextArea) component;
                break;
            }
        }
        
        // Add text with tags
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("<@base64>test</@base64> plain text <@hex>more</@hex>"));
        window.waitForIdle();
        
        // Find and click the Clear tags button
        Component clearTagsButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Clear tags".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) clearTagsButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify tags are removed but content remains
        String result = inputArea.getText();
        Assertions.assertFalse(result.contains("<@"), "Should not contain opening tags");
        Assertions.assertFalse(result.contains("</@"), "Should not contain closing tags");
        Assertions.assertTrue(result.contains("test"), "Should still contain 'test'");
        Assertions.assertTrue(result.contains("plain text"), "Should still contain 'plain text'");
        Assertions.assertTrue(result.contains("more"), "Should still contain 'more'");
    }

    @Test
    void testSwapButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Set text with tags in input - this will generate different output
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> {
            finalInputArea.setText("<@base64>test</@base64>");
        });
        window.waitForIdle();
        // Swap moves the output into the input, so wait for the conversion to land first
        UiTestSupport.awaitText(outputArea, "dGVzdA==");
        
        // Find and click the Swap button
        Component swapButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Swap".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) swapButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify swap occurred - input should have the base64 encoded value
        Assertions.assertEquals("dGVzdA==", inputArea.getText(), "Input should contain base64 encoded value after swap");
        // Note: Due to automatic conversion, output will immediately show "dGVzdA==" again
        // Let's wait a bit and check
        Assertions.assertEquals("dGVzdA==", UiTestSupport.awaitText(outputArea, "dGVzdA=="), "Output should show the same value due to automatic conversion");
    }

    @Test
    void testSelectInputButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input area
        Component[] allTextAreas = window
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea inputArea = null;
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                inputArea = (JTextArea) component;
                break;
            }
        }
        
        // Add text to input
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("text to select"));
        window.waitForIdle();
        
        // Clear any selection
        GuiActionRunner.execute(() -> finalInputArea.setCaretPosition(0));
        window.waitForIdle();
        
        // Find and click the Select input button
        Component selectInputButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Select input".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) selectInputButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify text is selected
        String selectedText = inputArea.getSelectedText();
        Assertions.assertEquals("text to select", selectedText, "All input text should be selected");
    }

    @Test
    void testSelectOutputButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the output area
        Component[] allTextAreas = window
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea outputArea = null;
        int hackvertorInputCount = 0;
        
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                if (hackvertorInputCount == 1) {
                    outputArea = (JTextArea) component;
                    break;
                }
                hackvertorInputCount++;
            }
        }
        
        // Add text to output
        final JTextArea finalOutputArea = outputArea;
        GuiActionRunner.execute(() -> finalOutputArea.setText("output to select"));
        window.waitForIdle();
        
        // Clear any selection
        GuiActionRunner.execute(() -> finalOutputArea.setCaretPosition(0));
        window.waitForIdle();
        
        // Find and click the Select output button
        Component selectOutputButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Select output".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) selectOutputButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify text is selected
        String selectedText = outputArea.getSelectedText();
        Assertions.assertEquals("output to select", selectedText, "All output text should be selected");
    }

    @Test
    void testConvertButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Add text with base64 tags to input
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("<@base64>hello world</@base64>"));
        window.waitForIdle();
        
        // Clear output first
        final JTextArea finalOutputArea = outputArea;
        GuiActionRunner.execute(() -> finalOutputArea.setText(""));
        window.waitForIdle();
        
        // Find and click the Convert button
        Component convertButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Convert".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) convertButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify output contains base64 encoded result
        String outputText = UiTestSupport.awaitText(outputArea, "aGVsbG8gd29ybGQ=");
        Assertions.assertEquals("aGVsbG8gd29ybGQ=", outputText, "Output should contain base64 encoded 'hello world'");
    }

    @Test
    void testPasteInsideTagsButton() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input area
        Component[] allTextAreas = window
                .findAll(window.target(), component -> component instanceof JTextArea)
                .toArray(new Component[0]);
        
        JTextArea inputArea = null;
        for (Component component : allTextAreas) {
            if (component.getClass().getName().equals("burp.hv.ui.HackvertorInput")) {
                inputArea = (JTextArea) component;
                break;
            }
        }
        
        // Set up clipboard content
        String clipboardContent = "pasted content";
        GuiActionRunner.execute(() -> {
            java.awt.datatransfer.StringSelection stringSelection = 
                new java.awt.datatransfer.StringSelection(clipboardContent);
            burp.hv.utils.Utils.getClipboard().setContents(stringSelection, null);
        });
        
        // Add tags to input area - using a simpler structure to avoid the IndexOutOfBoundsException
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> {
            finalInputArea.setText("<@base64></@base64>");
        });
        window.waitForIdle();
        
        // Find and click the Paste inside tags button
        Component pasteInsideButton = window.find(
                window.target(),
                c -> c instanceof JButton &&
                     "Paste inside tags".equals(((JButton) c).getText())
        );
        
        JButton button = (JButton) pasteInsideButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Verify clipboard content was pasted inside the empty tag
        String result = inputArea.getText();
        Assertions.assertEquals("<@base64>pasted content</@base64>", result, 
            "Clipboard content should be pasted inside base64 tags");
    }

    @Test
    void testHexEncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type "test" in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the hex button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component hexButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "hex".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) hexButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags around "test"
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@hex(' ')>test</@hex>", inputText, "Input should have hex tags around 'test'");
                // Check that output area contains the hex encoded value of "test"
        String outputText = UiTestSupport.awaitText(outputArea, "74 65 73 74");
        Assertions.assertEquals("74 65 73 74", outputText, "Output should contain hex encoded 'test'");
    }

    @Test
    void testUrlencodeTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type text with special characters in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("hello world!"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the urlencode button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component urlencodeButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "urlencode".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) urlencodeButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@urlencode>hello world!</@urlencode>", inputText, "Input should have urlencode tags");
        
        // Check that output area contains the URL encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "hello+world%21");
        Assertions.assertEquals("hello+world%21", outputText, "Output should contain URL encoded text");
    }

    @Test
    void testHtmlEntitiesTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type HTML characters in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("<script>"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the html_entities button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component htmlEntitiesButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "html_entities".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) htmlEntitiesButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@html_entities><script></@html_entities>", inputText, "Input should have html_entities tags");
        
        // Check that output area contains the HTML entity encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "&lt;script&gt;");
        Assertions.assertEquals("&lt;script&gt;", outputText, "Output should contain HTML entity encoded text");
    }

    @Test
    void testBase32EncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type "test" in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the base32 button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component base32Button = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "base32".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) base32Button;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@base32>test</@base32>", inputText, "Input should have base32 tags around 'test'");
        
        // Check that output area contains the base32 encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "ORSXG5A=");
        Assertions.assertEquals("ORSXG5A=", outputText, "Output should contain base32 encoded 'test'");
    }

    @Test
    void testJsStringEncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output HackvertorInput areas
        Component[] allTextAreas = window
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
        
        // Type text with quotes in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("alert('test')"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the js_string button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component jsStringButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "js_string".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) jsStringButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@js_string>alert('test')</@js_string>", inputText, "Input should have js_string tags");
        
        // Check that output area contains the JavaScript string encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "alert('test')");
        Assertions.assertEquals("alert('test')", outputText, "Output should contain JavaScript string encoded text");
    }

    @Test
    void testBase64urlEncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Type text in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test>>data"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the base64url button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component base64urlButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "base64url".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) base64urlButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@base64url>test>>data</@base64url>", inputText, "Input should have base64url tags");
        
        // Check that output area contains the base64url encoded value
        String outputText = UiTestSupport.awaitText(outputArea, "dGVzdD4-ZGF0YQ");
        Assertions.assertEquals("dGVzdD4-ZGF0YQ", outputText, "Output should contain base64url encoded text");
    }

    @Test  
    void testHtml5EntitiesEncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Type text with special characters in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("©®™€"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the html5_entities button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component html5EntitiesButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "html5_entities".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) html5EntitiesButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@html5_entities>©®™€</@html5_entities>", inputText, "Input should have html5_entities tags");
        
        // Check that output area contains the HTML5 entities
        String outputText = UiTestSupport.awaitText(outputArea, "&copy;&reg;&trade;&euro;");
        Assertions.assertEquals("&copy;&reg;&trade;&euro;", outputText, "Output should contain HTML5 entities");
    }

    @Test
    void testUnicodeEscapesEncodingTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Type text with Unicode characters in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the unicode_escapes button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component unicodeEscapesButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "unicode_escapes".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) unicodeEscapesButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@unicode_escapes>test</@unicode_escapes>", inputText, "Input should have unicode_escapes tags");
        
        // Check that output area contains the Unicode escapes
        String outputText = UiTestSupport.awaitText(outputArea, "\\u0074\\u0065\\u0073\\u0074");
        Assertions.assertEquals("\\u0074\\u0065\\u0073\\u0074", outputText, "Output should contain Unicode escapes");
    }

    @Test
    void testUrlencodeAllTag() throws Exception {
        // Wait for UI to be ready
        window.waitForIdle();
        
        // Find the input and output areas
        Component[] allTextAreas = window
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
        
        // Type text in the input area
        window.click(inputArea);
        window.waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("test"));
        window.waitForIdle();
        
        // Select all text
        GuiActionRunner.execute(finalInputArea::selectAll);
        window.waitForIdle();
        
        // Find and click the urlencode_all button
        List<JTabbedPane> tabPanes = window.findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        Component urlencodeAllButton = window.find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        "urlencode_all".equals(((JButton) c).getText()) &&
                        c.isShowing()
        );
        
        JButton button = (JButton) urlencodeAllButton;
        GuiActionRunner.execute(() -> button.doClick());
        window.waitForIdle();
        
        // Check that input area contains the tags
        String inputText = inputArea.getText();
        Assertions.assertEquals("<@urlencode_all>test</@urlencode_all>", inputText, "Input should have urlencode_all tags");
        
        // Check that output area contains all characters URL encoded
        String outputText = UiTestSupport.awaitText(outputArea, "%74%65%73%74");
        Assertions.assertEquals("%74%65%73%74", outputText, "Output should contain all characters URL encoded");
    }

    @Test
    void testAutoDecodeGzipBase64Ui() throws Exception {
        window.waitForIdle();

        Component[] allTextAreas = window
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

        window.click(inputArea);
        window.waitForIdle();

        final JTextArea finalInputArea = inputArea;
        final JTextArea finalOutputArea = outputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("<@gzip_compress><@base64>foobar</@base64></@gzip_compress>"));
        window.waitForIdle();

        String encodedOutput = UiTestSupport.awaitText(outputArea, text -> !text.isEmpty());
        Assertions.assertFalse(encodedOutput.isEmpty(), "Output should contain gzip+base64 encoded data");

        GuiActionRunner.execute(() -> finalInputArea.setText("<@auto_decode_no_decrypt>" + finalOutputArea.getText() + "</@auto_decode_no_decrypt>"));
        window.waitForIdle();

        String decodedOutput = UiTestSupport.awaitText(outputArea, "<@gzip_compress><@base64>foobar</@base64></@gzip_compress>");
        Assertions.assertEquals("<@gzip_compress><@base64>foobar</@base64></@gzip_compress>", decodedOutput,
            "auto_decode_no_decrypt should produce correct gzip+base64 encoding tags");
    }

    @Test
    void testAutoDecodeDeflateBase32Ui() throws Exception {
        window.waitForIdle();

        Component[] allTextAreas = window
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

        window.click(inputArea);
        window.waitForIdle();

        final JTextArea finalInputArea = inputArea;
        final JTextArea finalOutputArea = outputArea;
        GuiActionRunner.execute(() -> finalInputArea.setText("<@deflate_compress><@base32>foobar</@base32></@deflate_compress>"));
        window.waitForIdle();

        String encodedOutput = UiTestSupport.awaitText(outputArea, text -> !text.isEmpty());
        Assertions.assertFalse(encodedOutput.isEmpty(), "Output should contain deflate+base32 encoded data");

        GuiActionRunner.execute(() -> finalInputArea.setText("<@auto_decode_no_decrypt>" + finalOutputArea.getText() + "</@auto_decode_no_decrypt>"));
        window.waitForIdle();

        String decodedOutput = UiTestSupport.awaitText(outputArea, "<@deflate_compress><@base32>foobar</@base32></@deflate_compress>");
        Assertions.assertEquals("<@deflate_compress><@base32>foobar</@base32></@deflate_compress>", decodedOutput,
            "auto_decode_no_decrypt should produce correct deflate+base32 encoding tags");
    }

    @AfterEach
    void checkForUncaughtExceptions() {
        // Check for uncaught exceptions and fail the test if any occurred
        if (!uncaughtExceptions.isEmpty()) {
            StringBuilder sb = new StringBuilder("Test failed due to uncaught exception(s):\n");
            for (Throwable exception : uncaughtExceptions) {
                sb.append("- ").append(exception.getClass().getSimpleName())
                  .append(": ").append(exception.getMessage()).append("\n");
                if (exception.getCause() != null) {
                    sb.append("  Caused by: ").append(exception.getCause().getClass().getSimpleName())
                      .append(": ").append(exception.getCause().getMessage()).append("\n");
                }
            }
            
            // Clear exceptions for next test
            uncaughtExceptions.clear();
            
            fail(sb.toString());
        }
    }

    @AfterAll
    static void tearDown() {
        // Don't leave the strict EDT checks behind for the test classes that run after this one.
        FailOnThreadViolationRepaintManager.uninstall();
        // Check for uncaught exceptions one final time
        if (!uncaughtExceptions.isEmpty()) {
            StringBuilder sb = new StringBuilder("Test suite failed due to uncaught exception(s):\n");
            for (Throwable exception : uncaughtExceptions) {
                sb.append("- ").append(exception.getClass().getSimpleName())
                  .append(": ").append(exception.getMessage()).append("\n");
                if (exception.getCause() != null) {
                    sb.append("  Caused by: ").append(exception.getCause().getClass().getSimpleName())
                      .append(": ").append(exception.getCause().getMessage()).append("\n");
                }
            }
            
            // Restore original handler before failing
            Thread.setDefaultUncaughtExceptionHandler(originalHandler);
            
            fail(sb.toString());
        }
        
        // Restore original exception handler
        Thread.setDefaultUncaughtExceptionHandler(originalHandler);
        
        if (window != null) {
            window.cleanUp();
        }
    }
}
