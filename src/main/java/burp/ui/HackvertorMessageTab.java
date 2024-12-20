package burp.ui;

import burp.BurpExtender;
import burp.Hackvertor;
import burp.IMessageEditorTab;
import burp.ui.HackvertorPanel;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;

public class HackvertorMessageTab implements IMessageEditorTab {
    private final JPanel hackvertorContainer = new JPanel(new BorderLayout());
    private HackvertorPanel hackvertorPanel;

    private byte[] currentMessage;
    private Boolean changed = false;
    private Boolean interfaceCreated = false;

    public HackvertorMessageTab(Hackvertor hackvertor) {
        hackvertorContainer.addHierarchyListener(e -> {
            if(e.getChangeFlags() == HierarchyEvent.SHOWING_CHANGED) {
                if(e.getComponent() == hackvertorContainer && hackvertorContainer.isShowing()) {
                    if(interfaceCreated) {
                        hackvertorPanel.getInputArea().setCaretPosition(0);
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        hackvertorPanel = new HackvertorPanel(hackvertor, false, BurpExtender.hideOutputInMessageEditor);
                        hackvertorPanel.getInputArea().getDocument().addDocumentListener(new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e1) {
                                changed = true;
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e1) {
                                changed = true;
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e1) {
                                changed = true;
                            }
                        });
                        hackvertorContainer.add(hackvertorPanel);
                        if (currentMessage != null) {
                            hackvertorPanel.getInputArea().setText(BurpExtender.helpers.bytesToString(currentMessage));
                            hackvertorPanel.getInputArea().setCaretPosition(0);
                        }
                        interfaceCreated = true;
                    });
                }
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "Hackvertor";
    }

    @Override
    public Component getUiComponent() {
        return hackvertorContainer;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content == null) {
            changed = false;
        } else {
            if (hackvertorPanel != null) {
                hackvertorPanel.getInputArea().setText(BurpExtender.helpers.bytesToString(content));
            }
        }
        currentMessage = content;
    }

    @Override
    public byte[] getMessage() {
        if (changed) {
            return BurpExtender.helpers.stringToBytes(hackvertorPanel.getInputArea().getText());
        } else {
            return currentMessage;
        }

    }

    @Override
    public boolean isModified() {
        return changed;
    }

    @Override
    public byte[] getSelectedData() {
        return BurpExtender.helpers.stringToBytes(hackvertorPanel.getInputArea().getSelectedText());
    }
}
