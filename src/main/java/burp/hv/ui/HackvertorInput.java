package burp.hv.ui;

import burp.IParameter;
import burp.IRequestInfo;

import javax.swing.*;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import static burp.hv.HackvertorExtension.*;

public class HackvertorInput extends JTextArea {
    public HackvertorInput() {
        super();
        HackvertorInput that = this;
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) { // Detect double-click
                    int clickPos = that.viewToModel(e.getPoint());
                    String text = that.getText();
                    IRequestInfo analyzedRequest = helpers.analyzeRequest(helpers.stringToBytes(text));
                    List<IParameter> params = analyzedRequest.getParameters();

                    for (IParameter param : params) {
                        int start = param.getValueStart();
                        int end = param.getValueEnd();

                        if (clickPos >= start && clickPos <= end) {
                            that.select(start, end);
                        }
                    }
                }
            }
        });
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
        SwingUtilities.invokeLater(this::getFontSizeFromBurp);
    }

    public void getFontSizeFromBurp() {
        callbacks.customizeUiComponent(this);
        this.changeFontSize(this.getFont().getSize());
    }

    public void changeFontSize(int fontSize) {
        this.setFont(new Font("Courier New", Font.PLAIN, fontSize));
    }
}
