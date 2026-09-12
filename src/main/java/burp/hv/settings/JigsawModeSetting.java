package burp.hv.settings;

import burp.api.montoya.persistence.Preferences;
import burp.hv.HackvertorExtension;

public class JigsawModeSetting {

    private static final String PREFERENCE_KEY = "jigsawMode";

    public static boolean isJigsawMode() {
        Preferences preferences = preferences();
        if (preferences == null) {
            return true;
        }
        Boolean stored = preferences.getBoolean(PREFERENCE_KEY);
        return stored == null || stored;
    }

    public static void setJigsawMode(boolean jigsawMode) {
        Preferences preferences = preferences();
        if (preferences != null) {
            preferences.setBoolean(PREFERENCE_KEY, jigsawMode);
        }
    }

    private static Preferences preferences() {
        return HackvertorExtension.montoyaApi == null ? null : HackvertorExtension.montoyaApi.persistence().preferences();
    }
}
