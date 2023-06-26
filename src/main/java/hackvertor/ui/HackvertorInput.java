package hackvertor.ui;

import hackvertor.HackvertorExtension;
import hackvertor.Utils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;

import java.awt.*;

public class HackvertorInput extends RSyntaxTextArea {
    public HackvertorInput() {
        super();
        HackvertorExtension.callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateUI() {
        super.updateUI();
        HackvertorExtension.isDarkTheme = HackvertorExtension.DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
        SwingUtilities.invokeLater(() -> {
            if(HackvertorExtension.isDarkTheme) {
                Utils.applyThemeToRSyntaxTextArea(this, "dark");
            } else {
                Utils.applyThemeToRSyntaxTextArea(this, "default");
            }
        });
        HackvertorExtension.callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateFont() {
        this.setFont(new Font("Courier New", Font.PLAIN, this.getFont().getSize()));
    }
}
