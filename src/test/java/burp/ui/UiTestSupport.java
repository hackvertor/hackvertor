package burp.ui;

import org.assertj.swing.edt.GuiActionRunner;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.util.function.Predicate;

public class UiTestSupport {

    public static final String TAG_MODE = "Tag mode";
    public static final String JIGSAW_MODE = "Jigsaw mode";

    private static final long AWAIT_TIMEOUT_MS = 5000;

    public static void selectInputMode(HeadlessWindow window, String mode) {
        JComboBox<?> selector = (JComboBox<?>) window.find(window.target(),
                component -> component instanceof JComboBox && "inputModeSelector".equals(component.getName()));
        GuiActionRunner.execute(() -> selector.setSelectedItem(mode));
        window.waitForIdle();
    }

    /**
     * The output is converted on a background thread, so it lands some time after the input changes.
     * Waits for the text to become expected and returns whatever it ended up as, for the caller to assert on.
     */
    public static String awaitText(JTextComponent component, String expected) {
        return awaitText(component, expected::equals);
    }

    public static String awaitText(JTextComponent component, Predicate<String> condition) {
        long deadline = System.currentTimeMillis() + AWAIT_TIMEOUT_MS;
        String text = GuiActionRunner.execute(() -> component.getText());
        while (!condition.test(text) && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            text = GuiActionRunner.execute(() -> component.getText());
        }
        return text;
    }
}
