package burp.settings;

import burp.hv.HackvertorExtension;
import burp.hv.settings.HotkeyModifier;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.Settings;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.utils.Utils;
import burp.stubs.StubCallbacks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JFrame;
import javax.swing.KeyStroke;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HotkeyModifierTest {

    @BeforeEach
    void setUp() {
        HackvertorExtension.generalSettings = new Settings("general", new StubCallbacks(new JFrame("Test")));
        Utils.registerGeneralSettings(HackvertorExtension.generalSettings);
    }

    @AfterEach
    void tearDown() {
        HackvertorExtension.generalSettings = null;
    }

    @Test
    void defaultsToCtrlAlt() throws Exception {
        assertEquals("Ctrl+Alt", HotkeyModifier.get());
        assertEquals("Ctrl+Alt+D", HotkeyModifier.combo("D"));
        assertEquals(KeyStroke.getKeyStroke("control alt D"), HotkeyModifier.keyStroke("D"));
    }

    @Test
    void usesCtrlShiftWhenConfigured() throws Exception {
        setModifier("Ctrl+Shift");
        assertEquals("Ctrl+Shift+D", HotkeyModifier.combo("D"));
        assertEquals(KeyStroke.getKeyStroke("control shift D"), HotkeyModifier.keyStroke("D"));
    }

    @Test
    void usesCtrlShiftAltWhenConfigured() throws Exception {
        setModifier("Ctrl+Shift+Alt");
        assertEquals("Ctrl+Shift+Alt+D", HotkeyModifier.combo("D"));
        assertEquals(KeyStroke.getKeyStroke("control shift alt D"), HotkeyModifier.keyStroke("D"));
    }

    @Test
    void usesAlternativeKeyOnlyForCtrlShift() throws Exception {
        assertEquals("Ctrl+Alt+V", HotkeyModifier.combo("V", "G"));
        setModifier("Ctrl+Shift+Alt");
        assertEquals("Ctrl+Shift+Alt+V", HotkeyModifier.combo("V", "G"));
        setModifier("Ctrl+Shift");
        assertEquals("Ctrl+Shift+G", HotkeyModifier.combo("V", "G"));
    }

    @Test
    void fallsBackToCtrlAltForUnknownValue() throws Exception {
        setModifier("Meta+Alt");
        assertEquals("Ctrl+Alt", HotkeyModifier.get());
    }

    @Test
    void fallsBackToCtrlAltWhenSettingsAreUnavailable() {
        HackvertorExtension.generalSettings = null;
        assertEquals("Ctrl+Alt", HotkeyModifier.get());
    }

    private void setModifier(String modifier) throws UnregisteredSettingException, InvalidTypeSettingException {
        HackvertorExtension.generalSettings.setString(HotkeyModifier.SETTING_NAME, modifier);
    }
}
