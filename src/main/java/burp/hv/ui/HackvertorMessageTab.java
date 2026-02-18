package burp.hv.ui;

import burp.hv.HackvertorExtension;
import burp.hv.Hackvertor;
import burp.IMessageEditorTab;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.HierarchyEvent;

import static burp.hv.HackvertorExtension.generalSettings;

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
                        boolean shouldShowOuput = false;
                        try {
                            shouldShowOuput = generalSettings.getBoolean("showOutputInMessageEditor");
                        } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                            throw new RuntimeException(ex);
                        }
                        hackvertorPanel = new HackvertorPanel(hackvertor, false, !shouldShowOuput, true);
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
                            // Set the text programmatically and avoid marking the tab as "changed".
                            hackvertorPanel.getInputArea().setText(HackvertorExtension.helpers.bytesToString(currentMessage));
                            changed = false;
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
                // Set text programmatically; don't treat this as a user edit.
                hackvertorPanel.getInputArea().setText(HackvertorExtension.helpers.bytesToString(content));
                changed = false;
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
