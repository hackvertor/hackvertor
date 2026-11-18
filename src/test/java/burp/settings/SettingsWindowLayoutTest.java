package burp.settings;

import burp.hv.HackvertorExtension;
import burp.hv.settings.Settings;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.GuiActionRunner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagLayout;
import java.awt.Point;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SettingsWindowLayoutTest {

    //Tall enough for every setting, as on a typical screen, so the settings should not need to scroll.
    private static final int SCREEN_HEIGHT = 2000;

    @BeforeEach
    void setUp() {
        StubCallbacks callbacks = new StubCallbacks();
        HackvertorExtension.callbacks = callbacks;
        HackvertorExtension.stderr = new PrintWriter(callbacks.getStderr(), true);
        HackvertorExtension.stdout = new PrintWriter(callbacks.getStdout(), true);
        HackvertorExtension.generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
    }

    @AfterEach
    void tearDown() {
        HackvertorExtension.generalSettings = null;
    }

    @Test
    void theButtonsAtTheBottomOfTheSettingsAreVisible() {
        //Laid out like the settings window's content pane, which is packed to its preferred size.
        JPanel window = GuiActionRunner.execute(() -> {
            JPanel contentPane = new JPanel(new GridBagLayout());
            contentPane.addNotify();
            contentPane.add(Settings.buildSettingsPane(null, SCREEN_HEIGHT), Settings.settingsPaneConstraints());
            contentPane.setSize(contentPane.getPreferredSize());
            contentPane.validate();
            return contentPane;
        });
        JButton update = (JButton) findButton(window, "Update");
        assertNotNull(update, "Update button should be present");
        Point onWindow = GuiActionRunner.execute(() -> {
            Point location = new Point(0, update.getHeight());
            return SwingUtilities.convertPoint(update, location, window);
        });
        assertTrue(update.getHeight() > 0, "Update button should be laid out");
        assertTrue(onWindow.y <= window.getHeight(),
                "Update button bottom (" + onWindow.y + ") should fit inside the window (" + window.getHeight() + ")");
    }

    private Component findButton(Container container, String text) {
        for (Component component : container.getComponents()) {
            if (component instanceof JButton button && text.equals(button.getText())) {
                return button;
            }
            if (component instanceof Container child) {
                Component found = findButton(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
