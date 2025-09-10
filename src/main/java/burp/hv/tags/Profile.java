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
import java.util.ArrayList;
import java.util.Collections;

import static burp.hv.HackvertorExtension.callbacks;

public class Profile {
    private static JSONArray profiles = new JSONArray();
    private static final String PROFILES_KEY = "hackvertor_profiles";
    
    public static void loadProfiles() {
        String profilesJson = callbacks.loadExtensionSetting(PROFILES_KEY);
        if (profilesJson != null && !profilesJson.isEmpty()) {
            try {
                profiles = new JSONArray(profilesJson);
            } catch (JSONException e) {
                profiles = new JSONArray();
            }
        }
    }
    
    public static void saveProfiles() {
        callbacks.saveExtensionSetting(PROFILES_KEY, profiles.toString());
    }
    
    public static JSONArray getProfiles() {
        if (profiles == null) {
            profiles = new JSONArray();
        }
        return profiles;
    }
    
    public static void showProfilesDialog() {
        JPanel profilesPanel = new JPanel(new BorderLayout());
        JFrame profilesWindow = Utils.getHackvertorWindowInstance();
        profilesWindow.getContentPane().removeAll();
        profilesWindow.getContentPane().setLayout(new BorderLayout());
        profilesWindow.setTitle("Manage Profiles");
        profilesWindow.setResizable(true);
        profilesWindow.setPreferredSize(new Dimension(800, 600));
        
        // Load profiles if not already loaded
        loadProfiles();
        
        // Create table model for profiles list
        String[] columnNames = {"Enabled", "Name", "Analysis", "Modification"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        // Populate table with existing profiles
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject profile = profiles.getJSONObject(i);
            String contexts = String.join(", ", getContextsFromProfile(profile));
            boolean enabled = profile.optBoolean("enabled", true);
            tableModel.addRow(new Object[]{
                enabled ? "✓" : "✗",
                profile.getString("name"),
                profile.getString("analysis"),
                contexts
            });
        }
        
        JTable profilesTable = new JTable(tableModel);
        profilesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tableScrollPane = new JScrollPane(profilesTable);
        tableScrollPane.setPreferredSize(new Dimension(750, 400));
        
        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton newButton = new JButton("New Profile");
        JButton editButton = new JButton("Edit Profile");
        JButton deleteButton = new JButton("Delete Profile");
        JButton exportButton = new JButton("Export to Clipboard");
        JButton importButton = new JButton("Import from Clipboard");
        
        // Initially disable edit and delete buttons
        editButton.setEnabled(false);
        deleteButton.setEnabled(false);
        
        // Add selection listener to enable/disable buttons
        profilesTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    boolean hasSelection = profilesTable.getSelectedRow() != -1;
                    editButton.setEnabled(hasSelection);
                    deleteButton.setEnabled(hasSelection);
                }
            }
        });
        
        // New Profile button action
        newButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showCreateEditProfileDialog(false, null, tableModel);
            }
        });
        
        // Edit Profile button action
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = profilesTable.getSelectedRow();
                if (selectedRow != -1) {
                    JSONObject profile = profiles.getJSONObject(selectedRow);
                    showCreateEditProfileDialog(true, profile, tableModel);
                }
            }
        });
        
        // Delete Profile button action
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = profilesTable.getSelectedRow();
                if (selectedRow != -1) {
                    int result = JOptionPane.showConfirmDialog(profilesWindow,
                        "Are you sure you want to delete this profile?",
                        "Confirm Delete",
                        JOptionPane.YES_NO_OPTION);
                    
                    if (result == JOptionPane.YES_OPTION) {
                        profiles.remove(selectedRow);
                        tableModel.removeRow(selectedRow);
                        saveProfiles();
                    }
                }
            }
        });
        
        // Export button action
        exportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection profilesJSON = new StringSelection(profiles.toString(2));
                clipboard.setContents(profilesJSON, null);
                JOptionPane.showMessageDialog(profilesWindow, 
                    "Profiles exported to clipboard successfully!", 
                    "Export Success", 
                    JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        // Import button action
        importButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(profilesWindow,
                    "This will replace all existing profiles. Continue?",
                    "Confirm Import",
                    JOptionPane.YES_NO_OPTION);
                
                if (result == JOptionPane.YES_OPTION) {
                    try {
                        String jsonData = (String) Toolkit.getDefaultToolkit()
                            .getSystemClipboard().getData(DataFlavor.stringFlavor);
                        if (jsonData != null && !jsonData.isEmpty()) {
                            JSONArray importedProfiles = new JSONArray(jsonData);
                            profiles = importedProfiles;
                            saveProfiles();
                            
                            // Refresh table
                            tableModel.setRowCount(0);
                            for (int i = 0; i < profiles.length(); i++) {
                                JSONObject profile = profiles.getJSONObject(i);
                                String contexts = String.join(", ", getContextsFromProfile(profile));
                                boolean enabled = profile.optBoolean("enabled", true);
                                tableModel.addRow(new Object[]{
                                    enabled ? "✓" : "✗",
                                    profile.getString("name"),
                                    profile.getString("analysis"),
                                    contexts
                                });
                            }
                            
                            JOptionPane.showMessageDialog(profilesWindow,
                                "Profiles imported successfully!",
                                "Import Success",
                                JOptionPane.INFORMATION_MESSAGE);
                        }
                    } catch (JSONException ex) {
                        JOptionPane.showMessageDialog(profilesWindow,
                            "Invalid JSON format: " + ex.getMessage(),
                            "Import Error",
                            JOptionPane.ERROR_MESSAGE);
                    } catch (UnsupportedFlavorException | IOException ex) {
                        JOptionPane.showMessageDialog(profilesWindow,
                            "Failed to read clipboard data: " + ex.getMessage(),
                            "Import Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });
        
        // Close button action
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                profilesWindow.setVisible(false);
                profilesWindow.getContentPane().removeAll();
            }
        });
        
        // Style buttons if not native theme
        if (!HackvertorExtension.isNativeTheme && !HackvertorExtension.isDarkTheme) {
            newButton.setBackground(Color.decode("#005a70"));
            newButton.setForeground(Color.white);
            editButton.setBackground(Color.decode("#005a70"));
            editButton.setForeground(Color.white);
            deleteButton.setBackground(Color.decode("#005a70"));
            deleteButton.setForeground(Color.white);
            exportButton.setBackground(Color.decode("#005a70"));
            exportButton.setForeground(Color.white);
            importButton.setBackground(Color.decode("#005a70"));
            importButton.setForeground(Color.white);
            closeButton.setBackground(Color.decode("#005a70"));
            closeButton.setForeground(Color.white);
        }
        
        buttonPanel.add(newButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
        buttonPanel.add(exportButton);
        buttonPanel.add(importButton);
        buttonPanel.add(closeButton);
        
        profilesPanel.add(tableScrollPane, BorderLayout.CENTER);
        profilesPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        profilesWindow.add(profilesPanel);
        profilesWindow.pack();
        profilesWindow.setLocationRelativeTo(null);
        profilesWindow.setVisible(true);
    }
    
    private static void showCreateEditProfileDialog(boolean isEdit, JSONObject existingProfile, DefaultTableModel tableModel) {
        JDialog dialog = new JDialog(Utils.getHackvertorWindowInstance(), 
            isEdit ? "Edit Profile" : "Create Profile", true);
        dialog.setLayout(new BorderLayout());
        dialog.setPreferredSize(new Dimension(600, 550));
        
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Name field
        JLabel nameLabel = new JLabel("Profile Name:");
        JTextField nameField = new JTextField();
        if (isEdit && existingProfile != null) {
            nameField.setText(existingProfile.getString("name"));
        }
        
        // Enabled checkbox
        JLabel enabledLabel = new JLabel("Status:");
        JCheckBox enabledCheckbox = new JCheckBox("Enabled");
        if (isEdit && existingProfile != null) {
            // Check if the profile has an enabled field, default to true for backward compatibility
            boolean enabled = existingProfile.optBoolean("enabled", true);
            enabledCheckbox.setSelected(enabled);
        } else {
            // Default to enabled for new profiles
            enabledCheckbox.setSelected(true);
        }
        
        // Analysis field
        JLabel analysisLabel = new JLabel("Analysis(Python):");
        JTextArea analysisArea = new JTextArea(3, 30);
        analysisArea.setLineWrap(true);
        analysisArea.setWrapStyleWord(true);
        JScrollPane analysisScroll = new JScrollPane(analysisArea);
        if (isEdit && existingProfile != null) {
            analysisArea.setText(existingProfile.getString("analysis"));
        }
        
        // Modification field
        JLabel modificationLabel = new JLabel("Modification(Python):");
        JTextArea modificationArea = new JTextArea(5, 30);
        modificationArea.setLineWrap(true);
        modificationArea.setWrapStyleWord(true);
        JScrollPane modificationScroll = new JScrollPane(modificationArea);
        if (isEdit && existingProfile != null) {
            modificationArea.setText(existingProfile.getString("modification"));
        }
        
        // Context checkboxes
        JLabel contextLabel = new JLabel("Apply to:");
        JPanel contextPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox requestCheckbox = new JCheckBox("Request");
        JCheckBox responseCheckbox = new JCheckBox("Response");
        
        if (isEdit && existingProfile != null) {
            JSONArray contexts = existingProfile.getJSONArray("contexts");
            for (int i = 0; i < contexts.length(); i++) {
                String context = contexts.getString(i);
                if ("request".equals(context)) {
                    requestCheckbox.setSelected(true);
                } else if ("response".equals(context)) {
                    responseCheckbox.setSelected(true);
                }
            }
        } else {
            // Default to request selected for new profiles
            requestCheckbox.setSelected(true);
        }
        
        contextPanel.add(requestCheckbox);
        contextPanel.add(responseCheckbox);
        
        // Add components to main panel
        int y = 0;
        mainPanel.add(nameLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(nameField, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.CENTER));
        
        mainPanel.add(enabledLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(enabledCheckbox, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.WEST));
        
        mainPanel.add(analysisLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.NORTHWEST));
        mainPanel.add(analysisScroll, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0.3, 5, 5, GridBagConstraints.CENTER));
        
        mainPanel.add(modificationLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.NORTHWEST));
        mainPanel.add(modificationScroll, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0.5, 5, 5, GridBagConstraints.CENTER));
        
        mainPanel.add(contextLabel, GridbagUtils.createConstraints(0, y, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, GridBagConstraints.WEST));
        mainPanel.add(contextPanel, GridbagUtils.createConstraints(1, y++, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, GridBagConstraints.CENTER));
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveButton = new JButton(isEdit ? "Update" : "Create");
        JButton cancelButton = new JButton("Cancel");
        
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String name = nameField.getText().trim();
                String analysis = analysisArea.getText().trim();
                String modification = modificationArea.getText().trim();
                
                // Validation
                if (name.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "Profile name cannot be empty", 
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
                
                // Create contexts array
                JSONArray contexts = new JSONArray();
                if (requestCheckbox.isSelected()) {
                    contexts.put("request");
                }
                if (responseCheckbox.isSelected()) {
                    contexts.put("response");
                }
                
                // Create or update profile
                JSONObject profile = new JSONObject();
                profile.put("name", name);
                profile.put("analysis", analysis);
                profile.put("modification", modification);
                profile.put("contexts", contexts);
                profile.put("enabled", enabledCheckbox.isSelected());
                
                if (isEdit) {
                    // Find and update existing profile
                    for (int i = 0; i < profiles.length(); i++) {
                        if (profiles.getJSONObject(i).getString("name").equals(existingProfile.getString("name"))) {
                            profiles.put(i, profile);
                            // Update table
                            String contextsStr = String.join(", ", getContextsFromProfile(profile));
                            tableModel.setValueAt(enabledCheckbox.isSelected() ? "✓" : "✗", i, 0);
                            tableModel.setValueAt(name, i, 1);
                            tableModel.setValueAt(analysis, i, 2);
                            tableModel.setValueAt(contextsStr, i, 3);
                            break;
                        }
                    }
                } else {
                    // Add new profile
                    profiles.put(profile);
                    // Add to table
                    String contextsStr = String.join(", ", getContextsFromProfile(profile));
                    tableModel.addRow(new Object[]{
                        enabledCheckbox.isSelected() ? "✓" : "✗",
                        name, 
                        analysis, 
                        contextsStr
                    });
                }
                
                saveProfiles();
                dialog.dispose();
            }
        });
        
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });
        
        // Style buttons if not native theme
        if (!HackvertorExtension.isNativeTheme && !HackvertorExtension.isDarkTheme) {
            saveButton.setBackground(Color.decode("#005a70"));
            saveButton.setForeground(Color.white);
            cancelButton.setBackground(Color.decode("#005a70"));
            cancelButton.setForeground(Color.white);
        }

        buttonPanel.add(cancelButton);
        buttonPanel.add(saveButton);

        dialog.add(mainPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.pack();
        dialog.setLocationRelativeTo(Utils.getHackvertorWindowInstance());
        dialog.setVisible(true);
    }
    
    private static ArrayList<String> getContextsFromProfile(JSONObject profile) {
        ArrayList<String> contexts = new ArrayList<>();
        JSONArray contextsArray = profile.getJSONArray("contexts");
        for (int i = 0; i < contextsArray.length(); i++) {
            contexts.add(contextsArray.getString(i));
        }
        return contexts;
    }
    
    // Method to apply profiles to content
    public static String applyProfiles(String content, String context) {
        loadProfiles();
        for (int i = 0; i < profiles.length(); i++) {
            JSONObject profile = profiles.getJSONObject(i);
            
            // Check if profile is enabled (default to true for backward compatibility)
            boolean enabled = profile.optBoolean("enabled", true);
            if (!enabled) {
                continue; // Skip disabled profiles
            }
            
            JSONArray contexts = profile.getJSONArray("contexts");
            
            // Check if this profile applies to the current context
            boolean appliesTo = false;
            for (int j = 0; j < contexts.length(); j++) {
                if (contexts.getString(j).equals(context)) {
                    appliesTo = true;
                    break;
                }
            }
            
            if (appliesTo) {
                String analysis = profile.getString("analysis");
                String modification = profile.getString("modification");
                
                // Apply the profile's analysis and modification
                // TODO: Implement Python execution for analysis and modification
                // For now, keeping the same replacement logic
                content = content.replaceAll(analysis, modification);
            }
        }
        return content;
    }
}