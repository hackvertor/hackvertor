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
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Comprehensive UI tests for all Hackvertor tag buttons in each category.
 * Tests navigation to each category tab and clicking each tag button.
 */
public class HackvertorAllTagsUiTest {

    private static FrameFixture window;
    private static JFrame frame;
    private static final int width = 1200;
    private static final int height = 1000;
    private static Thread.UncaughtExceptionHandler originalHandler;
    private static final ConcurrentLinkedQueue<Throwable> uncaughtExceptions = new ConcurrentLinkedQueue<>();

    @BeforeAll
    static void installRepaintManager() {
        // Set system properties for headless mode and better UI testing
        System.setProperty("java.awt.headless", "false"); // We need GUI for UI tests
        System.setProperty("javax.swing.disableQuestions", "true");
        System.setProperty("swing.disableOnEDT", "false");
        System.setProperty("awt.useSystemAAFontSettings", "on");
        
        FailOnThreadViolationRepaintManager.install();
        
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

        return message.contains("Cannot invoke \"javax.swing.text.View.getMinimumSpan") ||
               message.contains("Cannot invoke \"javax.swing.text.View.getPreferredSpan") ||
               message.contains("Cannot invoke \"javax.swing.text.View.getMaximumSpan") ||
               message.contains("Cannot invoke \"javax.swing.text.View.paint") ||
               message.contains("sun.swing.") ||
               message.contains("java.awt.EventQueue") ||
               (exception instanceof java.awt.IllegalComponentStateException);
    }

    @BeforeAll
    static void setUp() {
        SwingUtilities.invokeLater(() -> {
            frame = new JFrame("Burp Suite - Hackvertor");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setContentPane(new JPanel(new BorderLayout()));
            frame.setPreferredSize(new Dimension(width, height));
            JMenuBar menuBar = new JMenuBar();
            frame.setJMenuBar(menuBar);

            HackvertorExtension hackvertorExtension = new HackvertorExtension();
            hackvertorExtension.registerExtenderCallbacks(new StubCallbacks(frame));

            frame.pack();
            frame.setVisible(true);
        });

        // Wait until frame is ready before wrapping
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {}

        window = new FrameFixture(frame);
        window.show();
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
        
        window.cleanUp();
    }

    private void testTagButton(String categoryName, String buttonName, String inputText, String expectedTagPrefix) throws Exception {
        // Wait for UI to be ready with longer timeout
        window.robot().waitForIdle();
        Thread.sleep(100); // Additional small delay for UI stabilization
        
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
        
        // Set input text
        window.robot().click(inputArea);
        window.robot().waitForIdle();
        
        final JTextArea finalInputArea = inputArea;
        GuiActionRunner.execute(() -> {
            finalInputArea.setDocument(finalInputArea.getUI().getEditorKit(finalInputArea).createDefaultDocument());
            finalInputArea.setText(inputText);
        });
        window.robot().waitForIdle();

        GuiActionRunner.execute(finalInputArea::selectAll);
        window.robot().waitForIdle();
        
        // Find the tabbed pane and click on the category tab
        List<JTabbedPane> tabPanes = window.robot().finder().findAll(
                        c -> c instanceof JTabbedPane && c.isShowing()
                ).stream()
                .map(c -> (JTabbedPane) c)
                .toList();

        JTabbedPane innerTabs = tabPanes.get(0);
        
        // Find and click the category tab by name
        int categoryTabIndex = -1;
        for (int i = 0; i < innerTabs.getTabCount(); i++) {
            if (categoryName.equals(innerTabs.getTitleAt(i))) {
                categoryTabIndex = i;
                break;
            }
        }
        
        if (categoryTabIndex >= 0) {
            final int tabIndex = categoryTabIndex;
            GuiActionRunner.execute(() -> innerTabs.setSelectedIndex(tabIndex));
        } else {
            Assertions.fail("Could not find '" + categoryName + "' tab");
        }
        window.robot().waitForIdle();
        
        Component selectedTabContent = GuiActionRunner.execute(innerTabs::getSelectedComponent);

        // Find and click the button
        Component button = window.robot().finder().find(
                (Container) selectedTabContent,
                c -> c instanceof JButton &&
                        buttonName.equals(((JButton) c).getText())
        );
        
        JButton jButton = (JButton) button;
        GuiActionRunner.execute(() -> jButton.doClick());

        window.robot().waitForIdle();
        Thread.sleep(50);

        String actualInput = inputArea.getText();

        GuiActionRunner.execute(() -> {
            String currentText = finalInputArea.getText();
            finalInputArea.setDocument(finalInputArea.getUI().getEditorKit(finalInputArea).createDefaultDocument());
            finalInputArea.setText(currentText);
        });
        window.robot().waitForIdle();
        Assertions.assertTrue(actualInput.startsWith(expectedTagPrefix), 
            "Expected input to start with '" + expectedTagPrefix + "' but was: " + actualInput);
        Assertions.assertTrue(actualInput.contains(inputText), 
            "Expected input to contain '" + inputText + "' but was: " + actualInput);
        
        String outputText = outputArea.getText();
        System.out.println(buttonName + " output: " + outputText);

        final JTextArea finalOutputArea = outputArea;
        GuiActionRunner.execute(() -> {
            finalInputArea.setDocument(finalInputArea.getUI().getEditorKit(finalInputArea).createDefaultDocument());
            finalInputArea.setText("");
            finalOutputArea.setDocument(finalOutputArea.getUI().getEditorKit(finalOutputArea).createDefaultDocument());
            finalOutputArea.setText("");
        });
        window.robot().waitForIdle();
    }

    // ============ ENCODE CATEGORY TESTS ============
    
    @Test
    void testBase32Encode() throws Exception {
        testTagButton("Encode", "base32", "Hello", "<@base32>");
    }
    
    @Test
    void testBase58Encode() throws Exception {
        testTagButton("Encode", "base58", "Hello", "<@base58>");
    }
    
    @Test
    void testBase64Encode() throws Exception {
        testTagButton("Encode", "base64", "test", "<@base64>");
    }
    
    @Test
    void testBase64UrlEncode() throws Exception {
        testTagButton("Encode", "base64url", "Hello World!", "<@base64url>");
    }
    
    @Test
    void testHtmlEntitiesEncode() throws Exception {
        testTagButton("Encode", "html_entities", "<script>", "<@html_entities>");
    }
    
    @Test
    void testHtml5EntitiesEncode() throws Exception {
        testTagButton("Encode", "html5_entities", "<div>", "<@html5_entities>");
    }
    
    @Test
    void testHexEncode() throws Exception {
        testTagButton("Encode", "hex", "ABC", "<@hex");
    }
    
    @Test
    void testHexEntitiesEncode() throws Exception {
        testTagButton("Encode", "hex_entities", "ABC", "<@hex_entities>");
    }
    
    @Test
    void testHexEscapesEncode() throws Exception {
        testTagButton("Encode", "hex_escapes", "test", "<@hex_escapes>");
    }
    
    @Test
    void testOctalEscapesEncode() throws Exception {
        testTagButton("Encode", "octal_escapes", "test", "<@octal_escapes>");
    }
    
    @Test
    void testDecEntitiesEncode() throws Exception {
        testTagButton("Encode", "dec_entities", "ABC", "<@dec_entities>");
    }
    
    @Test
    void testUnicodeEscapesEncode() throws Exception {
        testTagButton("Encode", "unicode_escapes", "test", "<@unicode_escapes>");
    }
    
    @Test
    void testCssEscapesEncode() throws Exception {
        testTagButton("Encode", "css_escapes", "test", "<@css_escapes>");
    }
    
    @Test
    void testCssEscapes6Encode() throws Exception {
        testTagButton("Encode", "css_escapes6", "test", "<@css_escapes6>");
    }
    
    @Test
    void testBurpUrlEncode() throws Exception {
        testTagButton("Encode", "burp_urlencode", "Hello World", "<@burp_urlencode>");
    }
    
    @Test
    void testUrlEncode() throws Exception {
        testTagButton("Encode", "urlencode", "Hello World!", "<@urlencode>");
    }
    
    @Test
    void testUrlEncodeNotPlus() throws Exception {
        testTagButton("Encode", "urlencode_not_plus", "Hello World", "<@urlencode_not_plus>");
    }
    
    @Test
    void testUrlEncodeAll() throws Exception {
        testTagButton("Encode", "urlencode_all", "ABC", "<@urlencode_all>");
    }
    
    @Test
    void testPhpNonAlpha() throws Exception {
        testTagButton("Encode", "php_non_alpha", "test", "<@php_non_alpha>");
    }
    
    @Test
    void testPhpChr() throws Exception {
        testTagButton("Encode", "php_chr", "test", "<@php_chr>");
    }
    
    @Test
    void testSqlHex() throws Exception {
        testTagButton("Encode", "sql_hex", "test", "<@sql_hex>");
    }
    
    @Test
    void testPowershell() throws Exception {
        testTagButton("Encode", "powershell", "cmd", "<@powershell>");
    }
    
    @Test
    void testQuotedPrintable() throws Exception {
        testTagButton("Encode", "quoted_printable", "test=", "<@quoted_printable>");
    }
    
    @Test
    void testJsString() throws Exception {
        testTagButton("Encode", "js_string", "Hello\"World", "<@js_string>");
    }
    
    @Test
    void testUnicodeAlternatives() throws Exception {
        testTagButton("Encode", "unicode_alternatives", "test", "<@unicode_alternatives>");
    }
    
    @Test
    void testUtf7Encode() throws Exception {
        testTagButton("Encode", "utf7", "abc<>", "<@utf7");
    }
    
    @Test
    void testSamlEncode() throws Exception {
        testTagButton("Encode", "saml", "test", "<@saml>");
    }
    
    // ============ DECODE CATEGORY TESTS ============
    
    @Test
    void testBase32Decode() throws Exception {
        testTagButton("Decode", "d_base32", "JBSWY3DP", "<@d_base32>");
    }
    
    @Test
    void testBase58Decode() throws Exception {
        testTagButton("Decode", "d_base58", "9Ajdvzr", "<@d_base58>");
    }
    
    @Test
    void testBase64Decode() throws Exception {
        testTagButton("Decode", "d_base64", "dGVzdA==", "<@d_base64>");
    }
    
    @Test
    void testBase64UrlDecode() throws Exception {
        testTagButton("Decode", "d_base64url", "SGVsbG8gV29ybGQh", "<@d_base64url>");
    }
    
    @Test
    void testHtmlEntitiesDecode() throws Exception {
        testTagButton("Decode", "d_html_entities", "&lt;script&gt;", "<@d_html_entities>");
    }
    
    @Test
    void testHtml5EntitiesDecode() throws Exception {
        testTagButton("Decode", "d_html5_entities", "&lt;div&gt;", "<@d_html5_entities>");
    }
    
    @Test
    void testJsStringDecode() throws Exception {
        testTagButton("Decode", "d_js_string", "Hello\\\"World", "<@d_js_string>");
    }
    
    @Test
    void testBurpUrlDecode() throws Exception {
        testTagButton("Decode", "d_burp_url", "Hello%20World", "<@d_burp_url>");
    }
    
    @Test
    void testUrlDecode() throws Exception {
        testTagButton("Decode", "d_url", "Hello+World%21", "<@d_url>");
    }
    
    @Test
    void testCssEscapesDecode() throws Exception {
        testTagButton("Decode", "d_css_escapes", "\\74\\65\\73\\74", "<@d_css_escapes>");
    }
    
    @Test
    void testOctalEscapesDecode() throws Exception {
        testTagButton("Decode", "d_octal_escapes", "\\164\\145\\163\\164", "<@d_octal_escapes>");
    }
    
    @Test
    void testUnicodeEscapesDecode() throws Exception {
        testTagButton("Decode", "d_unicode_escapes", "\\u0074\\u0065\\u0073\\u0074", "<@d_unicode_escapes>");
    }
    
    @Test
    void testJwtGetPayload() throws Exception {
        testTagButton("Decode", "d_jwt_get_payload", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "<@d_jwt_get_payload>");
    }
    
    @Test
    void testJwtGetHeader() throws Exception {
        testTagButton("Decode", "d_jwt_get_header", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "<@d_jwt_get_header>");
    }
    
    @Test
    void testQuotedPrintableDecode() throws Exception {
        testTagButton("Decode", "d_quoted_printable", "test=3D", "<@d_quoted_printable>");
    }
    
    @Test
    void testUtf7Decode() throws Exception {
        testTagButton("Decode", "d_utf7", "Hi Mom +Jjo-", "<@d_utf7>");
    }
    
    @Test
    void testSamlDecode() throws Exception {
        testTagButton("Decode", "d_saml", "test", "<@d_saml>");
    }
    
    @Test
    void testAutoDecode() throws Exception {
        testTagButton("Decode", "auto_decode", "dGVzdA==", "<@auto_decode>");
    }
    
    @Test
    void testAutoDecodeNoDecrypt() throws Exception {
        testTagButton("Decode", "auto_decode_no_decrypt", "dGVzdA==", "<@auto_decode_no_decrypt>");
    }
    
    // ============ HASH CATEGORY TESTS ============
    
    @Test
    void testMd5Hash() throws Exception {
        testTagButton("Hash", "md5", "test", "<@md5>");
    }
    
    @Test
    void testSha1Hash() throws Exception {
        testTagButton("Hash", "sha1", "test", "<@sha1>");
    }
    
    @Test
    void testSha256Hash() throws Exception {
        testTagButton("Hash", "sha256", "test", "<@sha256>");
    }
    
    @Test
    void testSha512Hash() throws Exception {
        testTagButton("Hash", "sha512", "test", "<@sha512>");
    }
    
    @Test
    void testSha3Hash() throws Exception {
        testTagButton("Hash", "sha3", "test", "<@sha3>");
    }
    
    @Test
    void testMd2Hash() throws Exception {
        testTagButton("Hash", "md2", "test", "<@md2>");
    }
    
    @Test
    void testMd4Hash() throws Exception {
        testTagButton("Hash", "md4", "test", "<@md4>");
    }
    
    // ============ STRING CATEGORY TESTS ============
    
    @Test
    void testUppercase() throws Exception {
        testTagButton("String", "uppercase", "hello", "<@uppercase>");
    }
    
    @Test
    void testLowercase() throws Exception {
        testTagButton("String", "lowercase", "HELLO", "<@lowercase>");
    }
    
    @Test
    void testCapitalise() throws Exception {
        testTagButton("String", "capitalise", "hello world", "<@capitalise>");
    }
    
    @Test
    void testUncapitalise() throws Exception {
        testTagButton("String", "uncapitalise", "Hello World", "<@uncapitalise>");
    }
    
    @Test
    void testReverse() throws Exception {
        testTagButton("String", "reverse", "Hello", "<@reverse>");
    }
    
    @Test
    void testLength() throws Exception {
        testTagButton("String", "length", "Hello World", "<@length>");
    }
    
    @Test
    void testUnique() throws Exception {
        testTagButton("String", "unique", "aabbcc", "<@unique>");
    }
    
    @Test
    void testFromCharcode() throws Exception {
        testTagButton("String", "from_charcode", "72,101,108,108,111", "<@from_charcode>");
    }
    
    @Test
    void testToCharcode() throws Exception {
        testTagButton("String", "to_charcode", "Hello", "<@to_charcode>");
    }
    
    // ============ CONVERT CATEGORY TESTS ============
    
    @Test
    void testAscii2Hex() throws Exception {
        testTagButton("Convert", "ascii2hex", "ABC", "<@ascii2hex");
    }
    
    @Test
    void testHex2Ascii() throws Exception {
        testTagButton("Convert", "hex2ascii", "414243", "<@hex2ascii>");
    }
    
    @Test
    void testAscii2Bin() throws Exception {
        testTagButton("Convert", "ascii2bin", "A", "<@ascii2bin>");
    }
    
    @Test
    void testBin2Ascii() throws Exception {
        testTagButton("Convert", "bin2ascii", "01000001", "<@bin2ascii>");
    }
    
    // ============ ENCRYPT CATEGORY TESTS ============
    
    @Test
    void testRotN() throws Exception {
        testTagButton("Encrypt", "rotN", "Hello", "<@rotN");
    }
    
    @Test
    void testXor() throws Exception {
        testTagButton("Encrypt", "xor", "Hello", "<@xor");
    }
    
    @Test
    void testAtbashEncrypt() throws Exception {
        testTagButton("Encrypt", "atbash_encrypt", "Hello", "<@atbash_encrypt>");
    }
    
    // ============ DECRYPT CATEGORY TESTS ============
    
    @Test
    void testAtbashDecrypt() throws Exception {
        testTagButton("Decrypt", "atbash_decrypt", "Svool", "<@atbash_decrypt>");
    }
    
    // ============ COMPRESSION CATEGORY TESTS ============
    
    @Test
    void testGzipCompress() throws Exception {
        testTagButton("Compression", "gzip_compress", "Hello World", "<@gzip_compress>");
    }
    
    @Test
    void testGzipDecompress() throws Exception {
        // Use a simple gzipped "test" string
        testTagButton("Compression", "gzip_decompress", "H4sIAAAAAAAAA0tJLS4BAAx+f9gEAAAA", "<@gzip_decompress>");
    }
    
    @Test
    void testBzip2Compress() throws Exception {
        testTagButton("Compression", "bzip2_compress", "Hello World", "<@bzip2_compress>");
    }
    
    @Test
    void testBrotliDecompress() throws Exception {
        testTagButton("Compression", "brotli_decompress", "test", "<@brotli_decompress>");
    }
}