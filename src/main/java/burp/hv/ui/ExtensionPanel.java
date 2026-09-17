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

    /**
     * Guards against re-entering the change listener while a tab is being added. Inserting a tab
     * before the selected one makes JTabbedPane shift the selection and fire a change event, and
     * at that point "..." is still the selected tab, so without this the listener would add
     * another panel, and another, forever.
     */
    private boolean addingPanel = false;

    private final Hackvertor hackvertor;

    public ExtensionPanel(Hackvertor hackvertor){
        this.hackvertor = hackvertor;
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                HackvertorPanel selectedPanel = ExtensionPanel.this.getSelectedConvertorPanel();
                if (selectedPanel == null) {
                    return;
                }
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

        this.addFixedTabTitle(WhatsNewPanel.TITLE);

        //TODO Move to HackvertorPanel class
        this.addTab("1", new HackvertorPanel(hackvertor, true, false, false));
        this.addFixedTabs();
        this.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                if (ExtensionPanel.this.addingPanel) {
                    return;
                }
                if (ExtensionPanel.this.getSelectedIndex() == -1) {
                    return;
                }
                if (ExtensionPanel.this.clickedDelete) {
                    ExtensionPanel.this.clickedDelete = false;
                    //Closing a tab can leave a fixed tab selected, which would show an empty panel.
                    if (ExtensionPanel.this.getSelectedConvertorPanel() == null
                            && !ExtensionPanel.this.selectNearestConvertorTab()) {
                        ExtensionPanel.this.addNewPanel();
                    }
                    return;
                }
                if (ExtensionPanel.this.getTitleAt(ExtensionPanel.this.getSelectedIndex()).equals("...")) {
                    ExtensionPanel.this.addNewPanel();
                } else {
                    // Refresh history when a regular tab is selected
                    HackvertorPanel selectedPanel = ExtensionPanel.this.getSelectedConvertorPanel();
                    if (selectedPanel != null) {
                        selectedPanel.refreshHistory();
                    }
                }
            }
        });
    }

    /**
     * The selected convertor panel, or null when a fixed tab such as "..." or What's new is selected.
     */
    public HackvertorPanel getSelectedConvertorPanel() {
        int index = getSelectedIndex();
        if (index < 0 || index >= getTabCount()) {
            return null;
        }
        return getComponentAt(index) instanceof HackvertorPanel panel ? panel : null;
    }

    /**
     * Selects the convertor tab nearest to the current selection, preferring the one to the left.
     * Returns false when there are no convertor tabs left.
     */
    private boolean selectNearestConvertorTab() {
        for (int i = Math.min(getSelectedIndex(), getTabCount() - 1); i >= 0; i--) {
            if (getComponentAt(i) instanceof HackvertorPanel) {
                setSelectedIndex(i);
                return true;
            }
        }
        for (int i = 0; i < getTabCount(); i++) {
            if (getComponentAt(i) instanceof HackvertorPanel) {
                setSelectedIndex(i);
                return true;
            }
        }
        return false;
    }

    /**
     * Adds the tabs that belong to the extension rather than the user. "..." has to stay directly
     * after the convertor tabs because that is what creates a new one when selected.
     */
    private void addFixedTabs() {
        this.addTab("...", new JPanel());
        this.addTab(WhatsNewPanel.TITLE, new WhatsNewPanel());
    }

    public void refresh() {
        HackvertorPanel selectedPanel = getSelectedConvertorPanel();
        if (selectedPanel == null) {
            return;
        }
        JTabbedPane tabs = selectedPanel.getTabs();
        int tabIndex = tabs.getSelectedIndex();
        String text = tabs.getTitleAt(tabIndex);
        if(text.equals("Custom")) {
            tabs.setComponentAt(tabIndex, TagUtils.createButtons(hackvertor.getTags(), selectedPanel.getInputArea(), Tag.Category.Custom, null, false, selectedPanel.getTagClickHandler()));
        }
    }

    public HackvertorPanel addNewPanel(){
        HackvertorPanel panel = new HackvertorPanel(hackvertor, true, false, false);
        tabCounter++;
        int index = this.indexOfTab("...");
        if (index == -1) {
            index = this.getTabCount();
        }
        addingPanel = true;
        try {
            this.insertTab(String.valueOf(tabCounter), null, panel, null, index);
            this.setSelectedIndex(index);
        } finally {
            addingPanel = false;
        }
        panel.refreshHistory();
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
                if (this.isFixedTab(i)) {
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
        if(montoyaApi == null) {
            return;
        }
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

                HackvertorPanel panel = new HackvertorPanel(hackvertor, true, false, false);
                panel.getInputArea().setText(input);
                panel.getOutputArea().setText(output);

                // Add the tab - this will create the CloseButtonTab component
                this.addTab(name, panel);

                // Now set the actual tab title in the text field
                this.setActualTabTitle(i, name);
            }

            this.addFixedTabs();

            // Restore tab counter
            if (state.has("tabCounter")) {
                tabCounter = state.getInt("tabCounter");
            }

            // Restore selected index
            if (state.has("selectedIndex")) {
                int selectedIndex = state.getInt("selectedIndex");
                if (selectedIndex >= 0 && selectedIndex < tabsState.length()) {
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
            this.addTab("1", new HackvertorPanel(hackvertor, true, false, false));
            this.addFixedTabs();
            tabCounter = 1;
        }
    }

}
