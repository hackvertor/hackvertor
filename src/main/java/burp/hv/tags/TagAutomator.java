package burp.hv.tags;

import burp.hv.HackvertorExtension;
import burp.hv.utils.GridbagUtils;
import burp.hv.utils.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import static burp.hv.HackvertorExtension.callbacks;

public class TagAutomator {
    private static final String warningMsg = "Warning: These rules can slow down Burp Suite and increase memory usage. Be very careful with the Python you write. Avoid enabling them across many tools, and keep the number of rules as low as possible to reduce performance impact.";
    private static JSONArray rules = new JSONArray();
    private static final String RULES_KEY = "hackvertor_rules";
    
    public static void loadRules() {
        String rulesJson = callbacks.loadExtensionSetting(RULES_KEY);
        if (rulesJson != null && !rulesJson.isEmpty()) {
            try {
                rules = new JSONArray(rulesJson);
            } catch (JSONException e) {
                rules = new JSONArray();
            }
        }
    }
    
    public static void saveRules() {
        callbacks.saveExtensionSetting(RULES_KEY, rules.toString());
    }
    
    public static JSONArray getRules() {
        if (rules == null) {
            rules = new JSONArray();
        }
        return rules;
    }
    
    public static void showRulesDialog() {
        JPanel rulesPanel = new JPanel(new BorderLayout());
        JFrame rulesWindow = Utils.getHackvertorWindowInstance();
        rulesWindow.getContentPane().removeAll();
        rulesWindow.getContentPane().setLayout(new BorderLayout());
        rulesWindow.setTitle("Manage rules");
        rulesWindow.setResizable(true);
        rulesWindow.setPreferredSize(new Dimension(800, 600));

        loadRules();

        String[] columnNames = {"Enabled", "Type", "Name", "Analysis", "Modification", "Context"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);
            String contexts = String.join(", ", getContextsFromRule(rule));
            boolean enabled = rule.optBoolean("enabled", true);
            String ruleType = rule.optString("type", "Context Menu");
            tableModel.addRow(new Object[]{
                enabled ? "✓" : "✗",
                ruleType,
                rule.getString("name"),
                rule.getString("analysis"),
                rule.getString("modification"),
                contexts
            });
        }
        
        JTable rulesTable = new JTable(tableModel);
        rulesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tableScrollPane = new JScrollPane(rulesTable);
        tableScrollPane.setPreferredSize(new Dimension(750, 400));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton newButton = new JButton("New Rule");
        JButton editButton = new JButton("Edit Rule");
        JButton deleteButton = new JButton("Delete Rule");
        JButton exportButton = new JButton("Export to Clipboard");
        JButton importButton = new JButton("Import from Clipboard");

        editButton.setEnabled(false);
        deleteButton.setEnabled(false);

        rulesTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    boolean hasSelection = rulesTable.getSelectedRow() != -1;
                    editButton.setEnabled(hasSelection);
                    deleteButton.setEnabled(hasSelection);
                }
            }
        });

        newButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showCreateEditRuleDialog(false, null, tableModel);
            }
        });

        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = rulesTable.getSelectedRow();
                if (selectedRow != -1) {
                    JSONObject rule = rules.getJSONObject(selectedRow);
                    showCreateEditRuleDialog(true, rule, tableModel);
                }
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = rulesTable.getSelectedRow();
                if (selectedRow != -1) {
                    int result = JOptionPane.showConfirmDialog(rulesWindow,
                        "Are you sure you want to delete this rule?",
                        "Confirm Delete",
                        JOptionPane.YES_NO_OPTION);
                    
                    if (result == JOptionPane.YES_OPTION) {
                        rules.remove(selectedRow);
                        tableModel.removeRow(selectedRow);
                        saveRules();
                    }
                }
            }
        });

        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection rulesJSON = new StringSelection(rules.toString(2));
                clipboard.setContents(rulesJSON, null);
                JOptionPane.showMessageDialog(rulesWindow,
                    "Rules exported to clipboard successfully!",
                    "Export Success", 
                    JOptionPane.INFORMATION_MESSAGE);
            }
        });

        importButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(rulesWindow,
                    "This will replace all existing rules. Continue?",
                    "Confirm Import",
                    JOptionPane.YES_NO_OPTION);
                
                if (result == JOptionPane.YES_OPTION) {
                    try {
                        String jsonData = (String) Toolkit.getDefaultToolkit()
                            .getSystemClipboard().getData(DataFlavor.stringFlavor);
                        if (jsonData != null && !jsonData.isEmpty()) {
                            JSONArray importedRules = new JSONArray(jsonData);
                            rules = importedRules;
                            saveRules();

                            tableModel.setRowCount(0);
                            for (int i = 0; i < rules.length(); i++) {
                                JSONObject rule = rules.getJSONObject(i);
                                String contexts = String.join(", ", getContextsFromRule(rule));
                                boolean enabled = rule.optBoolean("enabled", true);
                                String ruleType = rule.optString("type", "Context Menu");
                                tableModel.addRow(new Object[]{
                                    enabled ? "✓" : "✗",
                                    ruleType,
                                    rule.getString("name"),
                                    rule.getString("analysis"),
                                    rule.getString("modification"),
                                    contexts
                                });
                            }
                            
                            JOptionPane.showMessageDialog(rulesWindow,
                                "Rules imported successfully!",
                                "Import Success",
                                JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (JSONException ex) {
                        JOptionPane.showMessageDialog(rulesWindow,
                            "Invalid JSON format: " + ex.getMessage(),
                            "Import Error",
                            JOptionPane.ERROR_MESSAGE);
                    } catch (UnsupportedFlavorException | IOException ex) {
                        JOptionPane.showMessageDialog(rulesWindow,
                            "Failed to read clipboard data: " + ex.getMessage(),
                            "Import Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                rulesWindow.setVisible(false);
                rulesWindow.getContentPane().removeAll();
            }
        });
        
        buttonPanel.add(newButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
        buttonPanel.add(exportButton);
        buttonPanel.add(importButton);
        buttonPanel.add(closeButton);
        rulesPanel.add(buildWarning(warningMsg), BorderLayout.NORTH);
        rulesPanel.add(tableScrollPane, BorderLayout.CENTER);
        rulesPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        rulesWindow.add(rulesPanel);
        rulesWindow.pack();
        rulesWindow.setLocationRelativeTo(null);
        rulesWindow.setVisible(true);
    }
    
    private static JSONArray loadExamples() {
        try {
            InputStream inputStream = TagAutomator.class.getResourceAsStream("/tag-automator-examples.json");
            if (inputStream != null) {
                InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
                StringBuilder jsonContent = new StringBuilder();
                char[] buffer = new char[1024];
                int length;
                while ((length = reader.read(buffer)) > 0) {
                    jsonContent.append(buffer, 0, length);
                }
                reader.close();
                return new JSONArray(jsonContent.toString());
            }
        } catch (IOException | JSONException e) {
        }
        return new JSONArray();
    }

    private static void showCreateEditRuleDialog(boolean isEdit, JSONObject existingRule, DefaultTableModel tableModel) {
        JDialog dialog = new JDialog(Utils.getHackvertorWindowInstance(),
            isEdit ? "Edit Rule" : "Create Rule", true);
        dialog.setLayout(new BorderLayout());
        dialog.setPreferredSize(new Dimension(800, 750));

        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JLabel examplesLabel = new JLabel("Examples:");
        JSONArray examples = loadExamples();
        String[] exampleNames = new String[examples.length() + 1];
        exampleNames[0] = "-- Select an example --";
        for (int i = 0; i < examples.length(); i++) {
            exampleNames[i + 1] = examples.getJSONObject(i).getString("name");
        }
        JComboBox<String> examplesComboBox = new JComboBox<>(exampleNames);

        JLabel typeLabel = new JLabel("Rule Type:");
        String[] ruleTypes = {"Context Menu", "HTTP"};
        JComboBox<String> typeComboBox = new JComboBox<>(ruleTypes);
        if (isEdit && existingRule != null) {
            String ruleType = existingRule.optString("type", "Context Menu");
            typeComboBox.setSelectedItem(ruleType);
        } else {
            typeComboBox.setSelectedItem("Context Menu");
        }

        JLabel nameLabel = new JLabel("Rule Name:");
        JTextField nameField = new JTextField();
        if (isEdit && existingRule != null) {
            nameField.setText(existingRule.getString("name"));
        }

        JLabel enabledLabel = new JLabel("Status:");
        JCheckBox enabledCheckbox = new JCheckBox("Enabled");
        if (isEdit && existingRule != null) {
            boolean enabled = existingRule.optBoolean("enabled", true);
            enabledCheckbox.setSelected(enabled);
        } else {
            enabledCheckbox.setSelected(true);
        }

        JLabel analysisLabel = new JLabel("Analysis(Python):");
        JTextArea analysisArea = new JTextArea(6, 50);
        analysisArea.setLineWrap(true);
        analysisArea.setWrapStyleWord(true);
        JScrollPane analysisScroll = new JScrollPane(analysisArea);
        if (isEdit && existingRule != null) {
            analysisArea.setText(existingRule.getString("analysis"));
        }

        JLabel modificationLabel = new JLabel("Modification(Python):");
        JTextArea modificationArea = new JTextArea(8, 50);
        modificationArea.setLineWrap(true);
        modificationArea.setWrapStyleWord(true);
        JScrollPane modificationScroll = new JScrollPane(modificationArea);
        if (isEdit && existingRule != null) {
            modificationArea.setText(existingRule.getString("modification"));
        }

        JLabel contextLabel = new JLabel("Apply to:");
        JPanel contextPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox requestCheckbox = new JCheckBox("Request");
        JCheckBox responseCheckbox = new JCheckBox("Response");
        
        JLabel toolLabel = new JLabel("Tool:");
        String[] tools = {"Proxy", "Intruder", "Repeater", "Scanner", "Extensions"};
        JComboBox<String> toolComboBox = new JComboBox<>(tools);
        toolComboBox.setSelectedItem("Repeater");
        
        if (isEdit && existingRule != null) {
            JSONArray contexts = existingRule.getJSONArray("contexts");
            for (int i = 0; i < contexts.length(); i++) {
                String context = contexts.getString(i);
                if ("request".equals(context)) {
                    requestCheckbox.setSelected(true);
                } else if ("response".equals(context)) {
                    responseCheckbox.setSelected(true);
                }
            }
            String tool = existingRule.optString("tool", "Repeater");
            toolComboBox.setSelectedItem(tool);
        } else {
            requestCheckbox.setSelected(true);
        }
        
        contextPanel.add(requestCheckbox);
        contextPanel.add(responseCheckbox);

        examplesComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedIndex = examplesComboBox.getSelectedIndex();
                if (selectedIndex > 0) {
                    JSONObject example = examples.getJSONObject(selectedIndex - 1);

                    typeComboBox.setSelectedItem(example.getString("type"));
                    nameField.setText(example.getString("name"));
                    analysisArea.setText(example.getString("analysis"));
                    modificationArea.setText(example.getString("modification"));
                    enabledCheckbox.setSelected(example.optBoolean("enabled", true));

                    requestCheckbox.setSelected(false);
                    responseCheckbox.setSelected(false);
                    JSONArray contexts = example.getJSONArray("contexts");
                    for (int i = 0; i < contexts.length(); i++) {
                        String context = contexts.getString(i);
                        if ("request".equals(context)) {
                            requestCheckbox.setSelected(true);
                        } else if ("response".equals(context)) {
                            responseCheckbox.setSelected(true);
                        }
                    }

                    String tool = example.optString("tool", "Repeater");
                    toolComboBox.setSelectedItem(tool);
                } else {
                    typeComboBox.setSelectedItem("Context Menu");
                    nameField.setText("");
                    analysisArea.setText("");
                    modificationArea.setText("");
                    enabledCheckbox.setSelected(true);
                    requestCheckbox.setSelected(true);
                    responseCheckbox.setSelected(false);
                }
            }
        });

        int y = 0;
        mainPanel.add(buildWarning(warningMsg), GridbagUtils.createConstraints(0, y++, 2, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(examplesLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(examplesComboBox, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));

        mainPanel.add(typeLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(typeComboBox, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));
        
        mainPanel.add(nameLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(nameField, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.CENTER));
        
        mainPanel.add(enabledLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(enabledCheckbox, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));
        
        mainPanel.add(analysisLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.NORTHWEST));
        mainPanel.add(analysisScroll, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0.3, 5, 5, GridBagConstraints.CENTER));

        JButton testAnalysisButton = new JButton("Test Analysis");
        testAnalysisButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String testInput = JOptionPane.showInputDialog(dialog, "Enter test input:", "Test Analysis", JOptionPane.PLAIN_MESSAGE);
                if (testInput != null) {
                    HackvertorExtension.executorService.submit(() -> {
                        try {
                            String analysisCode = analysisArea.getText();
                            String result = burp.hv.Convertors.python(HackvertorExtension.globalVariables, testInput, analysisCode, HackvertorExtension.tagCodeExecutionKey, null, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                            JOptionPane.showMessageDialog(dialog, "Result: " + result, "Analysis Test Result", JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception ex) {
                            JOptionPane.showMessageDialog(dialog, "Error: " + ex.getMessage(), "Analysis Test Error", JOptionPane.ERROR_MESSAGE);
                        }
                    });
                }
            }
        });
        mainPanel.add(new JLabel(), GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(testAnalysisButton, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));
        
        mainPanel.add(modificationLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.NORTHWEST));
        mainPanel.add(modificationScroll, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0.5, 5, 5, GridBagConstraints.CENTER));

        JButton testModificationButton = new JButton("Test Modification");
        testModificationButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String testInput = JOptionPane.showInputDialog(dialog, "Enter test input:", "Test Modification", JOptionPane.PLAIN_MESSAGE);
                if (testInput != null) {
                    HackvertorExtension.executorService.submit(() -> {
                        try {
                            CustomTags.loadCustomTags();
                            String modificationCode = modificationArea.getText();
                            String result = burp.hv.Convertors.python(HackvertorExtension.globalVariables, testInput, modificationCode, HackvertorExtension.tagCodeExecutionKey, null, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                            JOptionPane.showMessageDialog(dialog, "Result: " + result, "Modification Test Result", JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception ex) {
                            JOptionPane.showMessageDialog(dialog, "Error: " + ex.getMessage(), "Modification Test Error", JOptionPane.ERROR_MESSAGE);
                        }
                    });
                }
            }
        });
        if (!HackvertorExtension.isNativeTheme && !HackvertorExtension.isDarkTheme) {
            testModificationButton.setBackground(Color.decode("#005a70"));
            testModificationButton.setForeground(Color.white);
        }
        mainPanel.add(new JLabel(), GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(testModificationButton, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));
        
        mainPanel.add(contextLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(contextPanel, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.CENTER));
        
        mainPanel.add(toolLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(toolComboBox, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveButton = new JButton(isEdit ? "Update" : "Create");
        JButton cancelButton = new JButton("Cancel");
        
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String name = nameField.getText().trim();
                String analysis = analysisArea.getText().trim();
                String modification = modificationArea.getText().trim();

                if (name.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Rule name cannot be empty",
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (analysis.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Analysis code cannot be empty", 
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (modification.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Modification code cannot be empty", 
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (!requestCheckbox.isSelected() && !responseCheckbox.isSelected()) {
                    JOptionPane.showMessageDialog(dialog, "At least one context must be selected", 
                        "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                String tool = toolComboBox.getSelectedItem().toString();
                if(!tool.equals("Repeater")) {
                    int confirm = JOptionPane.showConfirmDialog(null, "Running Python on every "+tool+" request or response can affect Burp's performance, are you sure?");
                    if(confirm != 0) {
                        return;
                    }
                }

                JSONArray contexts = new JSONArray();
                if (requestCheckbox.isSelected()) {
                    contexts.put("request");
                }
                if (responseCheckbox.isSelected()) {
                    contexts.put("response");
                }

                JSONObject rule = new JSONObject();
                rule.put("type", (String) typeComboBox.getSelectedItem());
                rule.put("name", name);
                rule.put("analysis", analysis);
                rule.put("modification", modification);
                rule.put("contexts", contexts);
                rule.put("enabled", enabledCheckbox.isSelected());
                rule.put("tool", (String) toolComboBox.getSelectedItem());
                
                if (isEdit) {
                    for (int i = 0; i < rules.length(); i++) {
                        if (rules.getJSONObject(i).getString("name").equals(existingRule.getString("name"))) {
                            rules.put(i, rule);
                            String contextsStr = String.join(", ", getContextsFromRule(rule));
                            tableModel.setValueAt(enabledCheckbox.isSelected() ? "✓" : "✗", i, 0);
                            tableModel.setValueAt((String) typeComboBox.getSelectedItem(), i, 1);
                            tableModel.setValueAt(name, i, 2);
                            tableModel.setValueAt(analysis, i, 3);
                            tableModel.setValueAt(modification, i, 4);
                            tableModel.setValueAt(contextsStr, i, 5);
                            break;
                        }
                    }
                } else {
                    rules.put(rule);
                    String contextsStr = String.join(", ", getContextsFromRule(rule));
                    tableModel.addRow(new Object[]{
                        enabledCheckbox.isSelected() ? "✓" : "✗",
                        (String) typeComboBox.getSelectedItem(),
                        name, 
                        analysis,
                        modification,
                        contextsStr
                    });
                }
                
                saveRules();
                dialog.dispose();
            }
        });
        
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });

        buttonPanel.add(cancelButton);
        buttonPanel.add(saveButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.pack();
        dialog.setLocationRelativeTo(Utils.getHackvertorWindowInstance());
        dialog.setVisible(true);
    }
    
    public static ArrayList<String> getContextsFromRule(JSONObject rule) {
        ArrayList<String> contexts = new ArrayList<>();
        JSONArray contextsArray = rule.getJSONArray("contexts");
        for (int i = 0; i < contextsArray.length(); i++) {
            contexts.add(contextsArray.getString(i));
        }
        return contexts;
    }

    public static boolean shouldApplyRules(String context, String tool, String type) {
        loadRules();
        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);

            boolean enabled = rule.optBoolean("enabled", true);
            if (!enabled) {
                continue;
            }
            if(!rule.getString("type").equals(type)) continue;
            JSONArray contexts = rule.getJSONArray("contexts");
            String ruleTool = rule.optString("tool", "Repeater");

            boolean appliesTo = false;
            for (int j = 0; j < contexts.length(); j++) {
                if (contexts.getString(j).equals(context)) {
                    appliesTo = true;
                    break;
                }
            }

            boolean toolMatches = ruleTool.equalsIgnoreCase(tool);

            if (appliesTo && toolMatches) {
                return true;
            }
        }
        return false;
    }

    public static String applyRules(String content, String context, String tool, String type) {
        return applyRules(content, context, tool, type, null);
    }
    
    public static String applyRules(String content, String context, String tool, String type, String specificRuleName) {
        loadRules();
        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);
            boolean enabled = rule.optBoolean("enabled", true);
            if (!enabled) {
                continue;
            }

            if(!rule.getString("type").equals(type)) continue;
            
            // If a specific rule name is provided, only apply that rule
            if (specificRuleName != null && !rule.getString("name").equals(specificRuleName)) {
                continue;
            }
            
            JSONArray contexts = rule.getJSONArray("contexts");
            String ruleTool = rule.optString("tool", "Repeater");

            boolean appliesTo = false;
            for (int j = 0; j < contexts.length(); j++) {
                if (contexts.getString(j).equals(context)) {
                    appliesTo = true;
                    break;
                }
            }
            
            boolean toolMatches = ruleTool.equalsIgnoreCase(tool);
            
            if (appliesTo && toolMatches) {
                String analysis = rule.getString("analysis");
                String modification = rule.getString("modification");
                
                try {
                    String analysisResult = burp.hv.Convertors.python(HackvertorExtension.globalVariables, 
                        content, analysis, HackvertorExtension.tagCodeExecutionKey, 
                        null, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);

                    if (analysisResult != null && !analysisResult.trim().isEmpty()) {
                        String[] positionSets = analysisResult.trim().split(";");

                        for (int j = positionSets.length - 1; j >= 0; j--) {
                            String positionSet = positionSets[j];
                            String[] positions = positionSet.trim().split(",");
                            
                            if (positions.length >= 2) {
                                try {
                                    int start = Integer.parseInt(positions[0].trim());
                                    int end = Integer.parseInt(positions[1].trim());

                                    if (start >= 0 && end > start && end <= content.length()) {
                                        String extractedContent = content.substring(start, end);

                                        String modificationResult = burp.hv.Convertors.python(HackvertorExtension.globalVariables, 
                                            extractedContent, modification, HackvertorExtension.tagCodeExecutionKey, 
                                            null, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);

                                        if (modificationResult != null) {
                                            content = content.substring(0, start) + modificationResult + content.substring(end);
                                        }
                                    }
                                } catch (NumberFormatException | StringIndexOutOfBoundsException ex) {
                                }
                            }
                        }
                    }
                } catch (Exception ex) {
                }
                
                // If a specific rule was requested, break after applying it
                if (specificRuleName != null) {
                    break;
                }
            }
        }
        return content;
    }

    static public JTextArea buildWarning(String msg) {
        JTextArea warning = new JTextArea(msg);
        warning.setLineWrap(true);
        warning.setWrapStyleWord(true);
        warning.setEditable(false);
        warning.setOpaque(false);
        warning.setFocusable(false);
        warning.setBorder(null);
        warning.setBorder(new EmptyBorder(10, 10, 10, 10));
        warning.setForeground(Color.decode("#fcb700"));
        return warning;
    }
}