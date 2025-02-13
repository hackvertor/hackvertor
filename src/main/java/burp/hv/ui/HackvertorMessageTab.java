package burp.hv.ui;

import burp.hv.HackvertorExtension;
import burp.hv.Hackvertor;
import burp.IMessageEditorTab;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.HierarchyEvent;

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
                        SwingUtilities.invokeLater(() -> {
                            hackvertorPanel.getInputArea().requestFocusInWindow();
                        });
                        return;
                    }
                    SwingUtilities.invokeLater(() -> {
                        hackvertorPanel = new HackvertorPanel(hackvertor, false, true);
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
                            hackvertorPanel.getInputArea().setText(HackvertorExtension.helpers.bytesToString(currentMessage));
                        }
                        interfaceCreated = true;
                        hackvertorPanel.getInputArea().requestFocusInWindow();
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
                hackvertorPanel.getInputArea().setText(HackvertorExtension.helpers.bytesToString(content));
            }
        }
        currentMessage = content;
    }

    @Override
    public byte[] getMessage() {
        if (changed) {
            return HackvertorExtension.helpers.stringToBytes(hackvertorPanel.getInputArea().getText());
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
        return HackvertorExtension.helpers.stringToBytes(hackvertorPanel.getInputArea().getSelectedText());
    }
}
