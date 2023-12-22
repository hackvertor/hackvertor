package burp.ui;

import burp.BurpExtender;
import burp.Utils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import static burp.BurpExtender.callbacks;

public class HackvertorInput extends RSyntaxTextArea {
    public HackvertorInput() {
        super();
        HackvertorInput that = this;
        this.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {

            }

            @Override
            public void keyPressed(KeyEvent e) {
                if ((e.getKeyCode() == KeyEvent.VK_PLUS || e.getKeyCode() == KeyEvent.VK_EQUALS) && (e.isMetaDown() || (e.getModifiersEx() & KeyEvent.CTRL_DOWN_MASK) != 0)) {
                    int fontSize = that.getFont().getSize();
                    that.changeFontSize(fontSize + 1);
                } else if ((e.getKeyCode() == KeyEvent.VK_MINUS) && (e.isMetaDown() || (e.getModifiersEx() & KeyEvent.CTRL_DOWN_MASK) != 0)) {
                    int fontSize = that.getFont().getSize();
                    that.changeFontSize(fontSize - 1);
                } else if ((e.isControlDown() || e.isMetaDown()) && (e.getKeyCode() == KeyEvent.VK_0)) {
                    getFontSizeFromBurp();
                }
            }

            @Override
            public void keyReleased(KeyEvent e) {

            }
        });
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
            getFontSizeFromBurp();
        });
    }

    public void getFontSizeFromBurp() {
        callbacks.customizeUiComponent(this);
        this.changeFontSize(this.getFont().getSize());
    }

    public void changeFontSize(int fontSize) {
        this.setFont(new Font("Courier New", Font.PLAIN, fontSize));
    }
}
