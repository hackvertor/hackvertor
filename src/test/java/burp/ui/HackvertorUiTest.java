package burp.ui;

import burp.hv.HackvertorExtension;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.FailOnThreadViolationRepaintManager;
import org.assertj.swing.fixture.FrameFixture;
import org.junit.jupiter.api.*;

import javax.swing.*;
import java.awt.*;

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

    @AfterEach
    void tearDown() {
        if (window != null) {
            window.cleanUp();
        }
    }
}
