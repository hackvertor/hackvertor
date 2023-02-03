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
        callbacks.customizeUiComponent(this);
        this.updateFont();
    }
    public void updateFont() {
        this.setFont(new Font("Courier New", Font.PLAIN, this.getFont().getSize()));
    }
}
