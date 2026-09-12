package burp.settings;

import burp.hv.HackvertorExtension;
import burp.hv.settings.HotkeyModifier;
import burp.hv.settings.Settings;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import org.assertj.swing.edt.GuiActionRunner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.Component;
import java.awt.Container;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HotkeyModifierSettingUiTest {

    private JFrame settingsWindow;

    @BeforeEach
    void setUp() {
        StubCallbacks callbacks = new StubCallbacks(new JFrame("Test"));
        HackvertorExtension.callbacks = callbacks;
        HackvertorExtension.stderr = new PrintWriter(callbacks.getStderr(), true);
        HackvertorExtension.stdout = new PrintWriter(callbacks.getStdout(), true);
        HackvertorExtension.generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
    }

    @AfterEach
    void tearDown() {
        if (settingsWindow != null) {
            GuiActionRunner.execute(() -> settingsWindow.dispose());
            settingsWindow = null;
        }
        HackvertorExtension.generalSettings = null;
    }

    @Test
    void theSettingsWindowRendersTheHotkeyModifierDropdown() {
        JComboBox<?> selector = hotkeyModifierSelector();
        assertNotNull(selector);
        assertEquals(HotkeyModifier.OPTIONS.length, selector.getItemCount());
        assertEquals(HotkeyModifier.CTRL_ALT, selector.getSelectedItem());
    }

    @Test
    void choosingAModifierChangesTheHotkeyCombos() {
        JComboBox<?> selector = hotkeyModifierSelector();
        GuiActionRunner.execute(() -> selector.setSelectedItem(HotkeyModifier.CTRL_SHIFT));
        assertEquals("Ctrl+Shift+D", HotkeyModifier.combo("D"));
    }

    private JComboBox<?> hotkeyModifierSelector() {
        JPanel settingsPanel = GuiActionRunner.execute(() -> {
            settingsWindow = new JFrame("Settings");
            try {
                return HackvertorExtension.generalSettings.buildInterface(settingsWindow, 200, 25, 10,
                        Settings.categoryColumns(), HackvertorExtension.generalSettings);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return (JComboBox<?>) findByName(settingsPanel, HotkeyModifier.SETTING_NAME);
    }

    private Component findByName(Container container, String name) {
        for (Component component : container.getComponents()) {
            if (name.equals(component.getName())) {
                return component;
            }
            if (component instanceof Container child) {
                Component found = findByName(child, name);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
