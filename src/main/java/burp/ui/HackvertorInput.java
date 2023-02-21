package burp.ui;

import burp.BurpExtender;
import burp.Utils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;

import java.awt.*;

import static burp.BurpExtender.callbacks;

public class HackvertorInput extends RSyntaxTextArea {
    public HackvertorInput() {
        super();
        callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateUI() {
        super.updateUI();
        BurpExtender.isDarkTheme = BurpExtender.DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
        SwingUtilities.invokeLater(() -> {
            if(BurpExtender.isDarkTheme) {
                Utils.applyThemeToRSyntaxTextArea(this, "dark");
            } else {
                Utils.applyThemeToRSyntaxTextArea(this, "default");
            }
        });
        callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateFont() {
        this.setFont(new Font("Courier New", Font.PLAIN, this.getFont().getSize()));
    }
}
