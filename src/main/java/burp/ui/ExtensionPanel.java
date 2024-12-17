package burp.ui;

import burp.*;

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
                if (ExtensionPanel.this.getSelectedIndex() == -1) {
                    return;
                }
                if(BurpExtender.allowAutoConvertClipboard) {
                    HackvertorPanel selectedPanel = (HackvertorPanel) getComponentAt(ExtensionPanel.this.getSelectedIndex());
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
            tabs.setComponentAt(tabIndex, Utils.createButtons(hackvertor.getTags(), selectedPanel.getInputArea(), Tag.Category.Custom, null, false));
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
