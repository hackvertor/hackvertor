package burp.ui;

import javax.swing.*;

import java.awt.*;

import static burp.BurpExtender.callbacks;

public class HackvertorInput extends JTextArea {
    HackvertorInput() {
        super();
        callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateUI() {
        super.updateUI();
        callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateFont() {
        this.setFont(new Font("Courier New", Font.PLAIN, this.getFont().getSize()));
    }
}
