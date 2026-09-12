package burp.hv.ui.jigsaw;

import burp.hv.HackvertorExtension;
import burp.hv.tags.Tag;

import java.awt.*;

public class JigsawColours {

    public static final Color SELECTION = new Color(232, 118, 0);
    public static final Color REMOVAL = new Color(198, 40, 40);
    public static final Color TEXT = Color.decode("#202020");
    public static final Color PARAMETER_NAME = Color.decode("#5a5a5a");
    public static final Color TEXT_PIECE = Color.decode("#e8e2d5");
    public static final Color EDITOR_BACKGROUND = Color.decode("#fffdf7");

    public static Color forCategory(Tag.Category category) {
        float hue = (float) category.ordinal() / Tag.Category.values().length;
        return Color.getHSBColor(hue, 0.35f, 0.93f);
    }

    public static Color board() {
        return HackvertorExtension.isDarkTheme ? Color.decode("#2b2b2b") : Color.decode("#f6f6f6");
    }

    public static Color grid() {
        return HackvertorExtension.isDarkTheme ? Color.decode("#3a3a3a") : Color.decode("#e2e2e2");
    }

    public static Color hint() {
        return HackvertorExtension.isDarkTheme ? Color.decode("#777777") : Color.decode("#999999");
    }
}
