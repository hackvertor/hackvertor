package burp.hv.settings;

import burp.hv.HackvertorExtension;

import javax.swing.KeyStroke;

/**
 * The modifier used by all of Hackvertor's hotkeys.
 * <p>
 * Ctrl+Alt is the historical default but on Windows AltGr reports itself as Ctrl+Alt, so users of
 * keyboard layouts that type diacritics with AltGr trigger Hackvertor hotkeys while typing. Those
 * users can switch the modifier in the settings window instead.
 */
public class HotkeyModifier {

    public static final String SETTING_NAME = "hotkeyModifier";
    public static final String CTRL_ALT = "Ctrl+Alt";
    public static final String CTRL_SHIFT = "Ctrl+Shift";
    public static final String CTRL_SHIFT_ALT = "Ctrl+Shift+Alt";
    public static final String[] OPTIONS = {CTRL_ALT, CTRL_SHIFT, CTRL_SHIFT_ALT};

    /**
     * The configured modifier in Burp hotkey notation, e.g. "Ctrl+Alt".
     */
    public static String get() {
        if (HackvertorExtension.generalSettings == null) {
            return CTRL_ALT;
        }
        String modifier;
        try {
            modifier = HackvertorExtension.generalSettings.getString(SETTING_NAME);
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            return CTRL_ALT;
        }
        for (String option : OPTIONS) {
            if (option.equals(modifier)) {
                return option;
            }
        }
        return CTRL_ALT;
    }

    /**
     * Burp hotkey combination for a key, e.g. "Ctrl+Alt+D".
     */
    public static String combo(String key) {
        return get() + "+" + key;
    }

    /**
     * Burp hotkey combination for a key, using an alternative key when the modifier is Ctrl+Shift.
     * Used where the Ctrl+Shift form would collide with an existing Ctrl+Shift hotkey.
     */
    public static String combo(String key, String keyWhenCtrlShift) {
        String modifier = get();
        return modifier + "+" + (modifier.equals(CTRL_SHIFT) ? keyWhenCtrlShift : key);
    }

    /**
     * Swing key stroke for a key, e.g. Ctrl+Alt+D.
     */
    public static KeyStroke keyStroke(String key) {
        return KeyStroke.getKeyStroke(swingModifier() + " " + key);
    }

    private static String swingModifier() {
        return switch (get()) {
            case CTRL_SHIFT -> "control shift";
            case CTRL_SHIFT_ALT -> "control shift alt";
            default -> "control alt";
        };
    }
}
