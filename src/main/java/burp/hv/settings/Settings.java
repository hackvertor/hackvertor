package burp.hv.settings;

import burp.IBurpExtenderCallbacks;
import burp.hv.HackvertorExtension;
import burp.hv.HackvertorHttpHandler;
import burp.hv.ai.AI;
import burp.hv.utils.GridbagUtils;
import burp.hv.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.*;

import static burp.hv.utils.GridbagUtils.addMarginToGbc;
import static burp.hv.utils.GridbagUtils.createConstraints;
import static burp.hv.HackvertorExtension.*;
import static java.awt.GridBagConstraints.CENTER;

public class Settings {
    private JSONObject settings = new JSONObject();
    private JSONObject defaults = new JSONObject();
    private HashMap<String, ArrayList<String>> categories = new HashMap<>();
    private final String settingsName;
    private IBurpExtenderCallbacks callbacks;
    private boolean isModified = false;

    public static void showSettingsWindow() {
        Settings settings = new Settings("general", HackvertorExtension.callbacks);
        Utils.registerGeneralSettings(settings);
        settings.load();
        JFrame settingsWindow = Utils.getHackvertorWindowInstance();
        settingsWindow.getContentPane().removeAll();
        settingsWindow.setTitle("Settings");
        settingsWindow.setResizable(false);
        settingsWindow.setPreferredSize(new Dimension(820, 660));
        Container pane = settingsWindow.getContentPane();
        try {
            Map<String, Integer> columns = new HashMap<>();
            columns.put("AI", 1);
            columns.put("Tag permissions", 1);
            columns.put("Statistics", 2);
            columns.put("Misc", 2);
            columns.put("Requests", 2);
            columns.put("System", 2);
            JPanel settingsInterface = settings.buildInterface(settingsWindow, 200, 25,10, columns, HackvertorExtension.generalSettings);
            settingsInterface.setAutoscrolls(true);
            settingsInterface.setPreferredSize(new Dimension(800, 620));
            JScrollPane settingsScroll = new JScrollPane(settingsInterface);
            settingsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            settingsScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
            pane.setLayout(new GridBagLayout());
            pane.add(settingsScroll, createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 1, 5, 5, CENTER));
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error building interface:" + e);
            HackvertorExtension.callbacks.printError(Arrays.toString(e.getStackTrace()));
            throw new RuntimeException(e);
        }
        settingsWindow.pack();
        settingsWindow.setLocationRelativeTo(null);
        settingsWindow.setVisible(true);
    }

    public enum SettingType  {
            Boolean, String, Password, Integer
    }

    public Settings(String settingsName, IBurpExtenderCallbacks callbacks) {
        this.settingsName = settingsName;
        this.callbacks = callbacks;
    }

    private void addCategory(String category, String name) {
        if(!categories.containsKey(category)){
            categories.put(category, new ArrayList<>());
        }
        categories.get(category).add(name);
    }

    public void registerBooleanSetting(String name, boolean defaultValue, String description, String category, String warning) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
           setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Boolean");
        setting.put("category", category);
        if(warning != null) {
            setting.put("warning", warning);
        }
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerStringSetting(String name, String defaultValue, String description, String category) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "String");
        setting.put("category", category);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerPasswordSetting(String name, String defaultValue, String description, String category) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Password");
        setting.put("category", category);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void registerIntegerSetting(String name, int defaultValue, String description, String category) {
        addCategory(category, name);
        JSONObject setting;
        if(this.settings.has(name)) {
            setting = (JSONObject) this.settings.get(name);
        } else {
            setting = new JSONObject();
        }
        setting.put("description", description);
        setting.put("default", defaultValue);
        setting.put("type", "Integer");
        setting.put("category", category);
        this.settings.put(name, setting);
        this.defaults.put(name, setting);
    }
    public void load() {
        String json = callbacks.loadExtensionSetting(this.settingsName);
        if(json == null) {
            return;
        }
        this.settings = new JSONObject(json);
    }
    public void save(){
        isModified = false;
        callbacks.saveExtensionSetting(this.settingsName, this.settings.toString());
    }
    public boolean getBoolean(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Boolean.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getBoolean("value");
            } else {
                return setting.getBoolean("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a boolean");
    }

    public String getString(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.String.name().equals(type) || SettingType.Password.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getString("value");
            } else {
                return setting.getString("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a string");
    }

    public int getInteger(String name) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Integer.name().equals(type)) {
            if(setting.has("value")) {
                return setting.getInt("value");
            } else {
                return setting.getInt("default");
            }
        }
        throw new InvalidTypeSettingException("The setting " + name + " expects a int");
    }

    public void setString(String name, String value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.String.name().equals(type) || SettingType.Password.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects a string");
    }
    public void setInteger(String name, int value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Integer.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects an int");
    }

    public void setBoolean(String name, boolean value) throws UnregisteredSettingException, InvalidTypeSettingException {
        JSONObject setting = this.getSetting(name);
        String type = setting.getString("type");
        if(SettingType.Boolean.name().equals(type)) {
            setting.put("value", value);
            isModified = true;
            return;
        }
        throw new InvalidTypeSettingException("Error setting " + name + " expects an boolean");
    }

    private JSONObject getSetting(String name) throws UnregisteredSettingException {
        if(!this.settings.has(name) && !this.defaults.has(name)) {
            throw new UnregisteredSettingException(name +" has not been registered.");
        }
        return this.settings.has(name) ? this.settings.getJSONObject(name) : this.defaults.getJSONObject(name);
    }

    private void updateField(String name, JTextField field, JSONObject currentSetting) {
        if(currentSetting.getString("type").equals("String") || currentSetting.getString("type").equals("Password")) {
            try {
                this.setString(name, field.getText());
            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                callbacks.printError(ex.toString());
                throw new RuntimeException(ex);
            }
        } else {
            try {
                this.setInteger(name, Integer.parseInt(field.getText()));
            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                callbacks.printError(ex.toString());
                throw new RuntimeException(ex);
            }
        }
    }
    private void updateBoolean(String name, boolean checked) {
        try {
            this.setBoolean(name, checked);
        } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
            callbacks.printError(ex.toString());
            throw new RuntimeException(ex);
        }
    }

    private void resetSettings() {
        Iterator<String> keys = this.settings.keys();
        while(keys.hasNext()) {
            String key = keys.next();
            JSONObject setting = (JSONObject) this.settings.get(key);
            if (setting != null) {
                setting.remove("value");
                isModified = true;
            }
        }
    }
    public JPanel buildInterface(JFrame settingsWindow, int componentWidth, int componentHeight, int spacing, Map<String, Integer> columns, Settings loadSettingObject) throws UnregisteredSettingException, InvalidTypeSettingException {
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        JLabel status = new JLabel(" ");
        Settings settings = this;
        JLabel logoLabel;
        if (isDarkTheme) {
            logoLabel = new JLabel(createImageIcon("/images/logo-dark.png", "logo"));
        } else {
            logoLabel = new JLabel(createImageIcon("/images/logo-light.png", "logo"));
        }
        JPanel logoContainer = new JPanel(new GridBagLayout());
        logoContainer.add(logoLabel, GridbagUtils.createConstraints(0, 0, 1, 1, 0, 0, 0, 0, GridBagConstraints.NORTH));
        JLabel versionLabel = new JLabel(version);
        logoContainer.add(versionLabel, GridbagUtils.createConstraints(0, 1, 1, 1, 0, 0, 0, 0, GridBagConstraints.SOUTH));
        settingsPanel.add(logoContainer, addMarginToGbc(createConstraints(0, 0, 2, GridBagConstraints.NONE, 1, 0, spacing, spacing, GridBagConstraints.NORTHEAST), 5, 5, 5, 5));
        JPanel column1 = new JPanel();
        column1.setLayout(new BoxLayout(column1, BoxLayout.Y_AXIS));
        JPanel column2 = new JPanel();
        column2.setLayout(new BoxLayout(column2, BoxLayout.Y_AXIS));
        for (Map.Entry<String, ArrayList<String>> categoryKeySet : categories.entrySet()) {
            String categoryName = categoryKeySet.getKey();
            JPanel categoryContainer = new JPanel();
            categoryContainer.setLayout(new GridBagLayout());
            if(!AI.isAiSupported() && categoryName.equals("AI")) {
                categoryContainer.setBorder(BorderFactory.createTitledBorder(categoryName));
                categoryContainer.setToolTipText(AI.featureMessage);
                categoryContainer.setBorder(BorderFactory.createTitledBorder(categoryName + " is not available"));
                categoryContainer.setEnabled(false);
            } else {
                categoryContainer.setBorder(BorderFactory.createTitledBorder(categoryName));
            }
            int componentRow = 0;
            for (String name : categoryKeySet.getValue()) {
                if(!this.settings.has(name)) {
                    this.settings.put(name, this.defaults.getJSONObject(name));
                }
                JSONObject currentSetting = this.settings.getJSONObject(name);
                switch (currentSetting.getString("type")) {
                    case "Password" -> {
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JPasswordField field = new JPasswordField();
                        field.setEchoChar('*');
                        field.setText(this.getString(name));
                        field.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0, 0));
                        categoryContainer.add(new JLabel(), createConstraints(1, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        componentRow++;
                        JPanel passwordContainer = new JPanel(new GridBagLayout());
                        passwordContainer.add(field, createConstraints(0, 0, 2, GridBagConstraints.BOTH, 1, 1, 5, 5, GridBagConstraints.CENTER));
                        JCheckBox checkBox = new JCheckBox();
                        checkBox.addItemListener(e -> {
                            if(e.getStateChange() == ItemEvent.SELECTED) {
                                field.setEchoChar('\u0000');
                            } else {
                                field.setEchoChar('*');
                            }
                        });
                        passwordContainer.add(checkBox, createConstraints(0, 1, 1, GridBagConstraints.WEST, 0, 0, 5, 5, GridBagConstraints.WEST));
                        passwordContainer.add(new JLabel("Show"), createConstraints(1, 1, 1, GridBagConstraints.NONE, 0, 0, 5, 5, GridBagConstraints.WEST));
                        categoryContainer.add(passwordContainer, createConstraints(0, componentRow, 2, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        field.getDocument().addDocumentListener(new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }
                        });
                        if(!AI.isAiSupported() && categoryName.equals("AI")) {
                            passwordContainer.setEnabled(false);
                        }
                    }
                    case "Integer", "String" -> {
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JTextField field = new JTextField();
                        if(currentSetting.getString("type").equals("String")) {
                            field.setText(this.getString(name));
                        } else {
                            field.setText(this.getInteger(name)+"");
                        }
                        field.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0,0));
                        categoryContainer.add(new JLabel(), createConstraints(1, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        componentRow++;
                        categoryContainer.add(field, createConstraints(0, componentRow, 2, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST));
                        field.getDocument().addDocumentListener(new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                settings.updateField(name, field, currentSetting);
                            }
                        });
                        if(!AI.isAiSupported() && categoryName.equals("AI")) {
                            field.setEnabled(false);
                        }
                    }
                    case "Boolean" -> {
                        JSONObject defaultSetting = this.defaults.getJSONObject(name);
                        boolean shouldWarn = defaultSetting.has("warning");
                        JLabel label = new JLabel(currentSetting.getString("description"));
                        label.setPreferredSize(new Dimension(componentWidth, componentHeight));
                        JCheckBox checkBox = new JCheckBox();
                        checkBox.setSelected(this.getBoolean(name));
                        checkBox.addActionListener(e -> {
                            boolean isChecked = checkBox.isSelected();
                            if(isChecked && shouldWarn) {
                                int confirm = JOptionPane.showConfirmDialog(checkBox, defaultSetting.getString("warning"));
                                if(confirm != 0) {
                                    checkBox.setSelected(false);
                                    isChecked = false;
                                }
                            }
                            this.updateBoolean(name, isChecked);
                        });
                        categoryContainer.add(label, addMarginToGbc(createConstraints(0, componentRow, 1, GridBagConstraints.BOTH, 1, 0, spacing, spacing, GridBagConstraints.WEST), 0, 5, 0,0));
                        categoryContainer.add(checkBox, createConstraints(1, componentRow, 1, GridBagConstraints.EAST, 0, 0, spacing, spacing, GridBagConstraints.EAST));
                        if(!AI.isAiSupported() && categoryName.equals("AI")) {
                            checkBox.setEnabled(false);
                            checkBox.setSelected(false);
                            label.setEnabled(false);
                        }
                    }
                    default -> {
                        throw new InvalidTypeSettingException("Unexpected type");
                    }
                }
                componentRow++;
            }
            int col = columns.get(categoryName);
            if(col == 1) {
                column1.add(categoryContainer);
                column1.add(Box.createVerticalStrut(10));
            } else {
                column2.add(categoryContainer);
                column2.add(Box.createVerticalStrut(10));
            }
        }

        settingsPanel.add(column1, addMarginToGbc(createConstraints(0, 1, 1, GridBagConstraints.HORIZONTAL, 1, 0, spacing, spacing, GridBagConstraints.NORTHWEST), 5, 5, 5, 5));
        settingsPanel.add(column2, addMarginToGbc(createConstraints(1, 1, 1, GridBagConstraints.HORIZONTAL, 1, 0, spacing, spacing, GridBagConstraints.NORTHWEST), 5, 5, 5, 5));
        JPanel buttonsContainer = new JPanel(new GridBagLayout());
        JButton closeSettingsBtn = new JButton("Close");
        JButton resetSettingsBtn = new JButton("Reset");
        resetSettingsBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you want to reset your settings?");
            if(confirm == 0) {
                this.resetSettings();
                this.save();
                loadSettingObject.load();
                status.setText("Successfully reset settings. Close to complete.");

            }
        });
        JButton updateSettingsBtn = new JButton("Update");
        updateSettingsBtn.addActionListener(e -> {
            this.save();
            loadSettingObject.load();
            status.setText("Successfully updated settings.");
        });
        int containerRow = 2;
        buttonsContainer.add(new Label(), GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        buttonsContainer.add(closeSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(resetSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(2, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(updateSettingsBtn, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(3, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsContainer.add(new Label(), GridbagUtils.createConstraints(4, 0, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        closeSettingsBtn.addActionListener(e -> {
            if(isModified) {
                int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you have unsaved settings?");
                if(confirm != 0) {
                    return;
                }
            }
            settingsWindow.setVisible(false);
            settingsWindow.getContentPane().removeAll();
        });
        buttonsContainer.add(status, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(0, 1, 5, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        settingsPanel.add(buttonsContainer, createConstraints(0, containerRow, 2, GridBagConstraints.NONE, 0, 0, spacing, spacing, GridBagConstraints.CENTER));
        settingsWindow.pack();
        settingsWindow.setLocationRelativeTo(null);
        settingsWindow.setVisible(true);
        return settingsPanel;
    }
}
