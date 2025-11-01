package burp.hv.ui;

import burp.hv.*;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.Tag;
import burp.hv.utils.TagUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

import static burp.hv.HackvertorExtension.montoyaApi;

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

    public void saveState() {
        try {
            JSONArray tabsState = new JSONArray();

            // Save all tabs except the "..." tab
            for (int i = 0; i < this.getTabCount(); i++) {
                String title = this.getTitleAt(i);
                if (title.equals("...")) {
                    continue;
                }

                try {
                    HackvertorPanel panel = (HackvertorPanel) this.getComponentAt(i);
                    JSONObject tabState = new JSONObject();
                    // Get the actual tab title from the text field if it exists
                    String actualTitle = this.getActualTabTitle(i);
                    tabState.put("name", actualTitle);
                    tabState.put("input", panel.getInputArea().getText());
                    tabState.put("output", panel.getOutputArea().getText());
                    tabsState.put(tabState);
                } catch (ClassCastException e) {
                    // Skip non-HackvertorPanel components
                }
            }

            // Save the selected tab index
            JSONObject state = new JSONObject();
            state.put("tabs", tabsState);
            state.put("selectedIndex", Math.min(this.getSelectedIndex(), tabsState.length() - 1));
            state.put("tabCounter", tabCounter);
            montoyaApi.persistence().extensionData().setString("extensionPanelState", state.toString());
        } catch (Exception e) {
            System.err.println("Failed to save ExtensionPanel state: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void restoreState() {
        try {
            String savedState = montoyaApi.persistence().extensionData().getString("extensionPanelState");
            if (savedState == null || savedState.isEmpty()) {
                return;
            }

            JSONObject state = new JSONObject(savedState);
            JSONArray tabsState = state.getJSONArray("tabs");

            if (tabsState.length() == 0) {
                return;
            }

            // Remove all existing tabs first
            this.removeAll();

            // Restore saved tabs
            for (int i = 0; i < tabsState.length(); i++) {
                JSONObject tabState = tabsState.getJSONObject(i);
                String name = tabState.getString("name");
                String input = tabState.getString("input");
                String output = tabState.getString("output");

                HackvertorPanel panel = new HackvertorPanel(hackvertor, true, false);
                panel.getInputArea().setText(input);
                panel.getOutputArea().setText(output);

                // Add the tab - this will create the CloseButtonTab component
                this.addTab(name, panel);

                // Now set the actual tab title in the text field
                this.setActualTabTitle(i, name);
            }

            // Add the "..." tab at the end
            this.addTab("...", new JPanel());

            // Restore tab counter
            if (state.has("tabCounter")) {
                tabCounter = state.getInt("tabCounter");
            }

            // Restore selected index
            if (state.has("selectedIndex")) {
                int selectedIndex = state.getInt("selectedIndex");
                if (selectedIndex >= 0 && selectedIndex < this.getTabCount() - 1) {
                    SwingUtilities.invokeLater(() -> {
                        this.setSelectedIndex(selectedIndex);
                    });
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to restore ExtensionPanel state: " + e.getMessage());
            e.printStackTrace();
            // If restoration fails, ensure we have at least the default setup
            this.removeAll();
            this.addTab("1", new HackvertorPanel(hackvertor, true, false));
            this.addTab("...", new JPanel());
            tabCounter = 1;
        }
    }

}
