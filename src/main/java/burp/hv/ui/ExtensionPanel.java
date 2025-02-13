package burp.hv.ui;

import burp.hv.*;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.Tag;
import burp.hv.utils.TagUtils;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

public class ExtensionPanel extends JTabbedPaneClosable {
    private int tabCounter = 1;

    private final Hackvertor hackvertor;

    public ExtensionPanel(Hackvertor hackvertor){
        this.hackvertor = hackvertor;
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                HackvertorPanel selectedPanel = (HackvertorPanel) getComponentAt(ExtensionPanel.this.getSelectedIndex());
                selectedPanel.getInputArea().requestFocusInWindow();
                boolean allowAutoConvertClipboard;
                if(HackvertorExtension.generalSettings == null) {
                    return;
                }
                try {
                    allowAutoConvertClipboard = HackvertorExtension.generalSettings.getBoolean("allowAutoConvertClipboard");
                } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                    HackvertorExtension.callbacks.printError("Error loading settings:" + ex);
                    throw new RuntimeException(ex);
                }
                if (ExtensionPanel.this.getSelectedIndex() == -1) {
                    return;
                }
                if(allowAutoConvertClipboard) {
                    selectedPanel.readClipboardAndDecode();
                }
            }
        });

        //TODO Move to HackvertorPanel class
        this.addTab("1", new HackvertorPanel(hackvertor, true, false));
        this.addTab("...", new JPanel());
        this.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                if (ExtensionPanel.this.getSelectedIndex() == -1) {
                    return;
                }
                if (ExtensionPanel.this.clickedDelete) {
                    ExtensionPanel.this.clickedDelete = false;
                    if (ExtensionPanel.this.getTabCount() > 1) {
                        if (ExtensionPanel.this.getSelectedIndex() == ExtensionPanel.this.getTabCount() - 1) {
                            ExtensionPanel.this.setSelectedIndex(ExtensionPanel.this.getTabCount() - 2);
                        }
                        return;
                    }
                }
                if (ExtensionPanel.this.getTitleAt(ExtensionPanel.this.getSelectedIndex()).equals("...")) {
                    tabCounter++;
                    HackvertorPanel panel = new HackvertorPanel(hackvertor, true, false);
                    ExtensionPanel.this.remove(ExtensionPanel.this.getSelectedIndex());
                    ExtensionPanel.this.addTab(tabCounter + "", panel);
                    ExtensionPanel.this.addTab("...", new JPanel());
                    ExtensionPanel.this.setSelectedIndex(ExtensionPanel.this.getTabCount() - 2);
                }
            }
        });
    }

    public void refresh() {
        int index = ExtensionPanel.this.getSelectedIndex();
        if (index == -1) {
            return;
        }
        HackvertorPanel selectedPanel = (HackvertorPanel) getComponentAt(index);
        JTabbedPane tabs = selectedPanel.getTabs();
        int tabIndex = tabs.getSelectedIndex();
        String text = tabs.getTitleAt(tabIndex);
        if(text.equals("Custom")) {
            tabs.setComponentAt(tabIndex, TagUtils.createButtons(hackvertor.getTags(), selectedPanel.getInputArea(), Tag.Category.Custom, null, false));
        }
    }

    public HackvertorPanel addNewPanel(){
        HackvertorPanel panel = new HackvertorPanel(hackvertor, true, false);
        tabCounter++;
        this.insertTab(String.valueOf(tabCounter), null, panel, null, this.getTabCount() - 1);
        this.setSelectedIndex(this.getTabCount() - 2);
        return panel;
    }

    public void makeActiveBurpTab(){
        JTabbedPane tabbedPane = (JTabbedPane) this.getParent();
        tabbedPane.setSelectedComponent(this);
    }

}
