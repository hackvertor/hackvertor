package burp.hv;

import burp.hv.utils.Utils;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Iterator;

public class Variables {
    public static void showGlobalVariablesWindow() {
        JPanel createVariablePanel = new JPanel();
        JFrame createVariableWindow = Utils.getHackvertorWindowInstance();
        createVariableWindow.getContentPane().removeAll();
        createVariableWindow.getContentPane().setLayout(new BorderLayout());
        createVariableWindow.setTitle("Global variables");
        createVariableWindow.setResizable(false);
        createVariableWindow.setPreferredSize(new Dimension(500, 200));
        createVariableWindow.setVisible(true);
        JLabel errorMessage = new JLabel();
        errorMessage.setPreferredSize(new Dimension(450, 25));
        errorMessage.setForeground(Color.red);

        JLabel variableLabel = new JLabel("Variable name");
        variableLabel.setPreferredSize(new Dimension(220, 25));
        JTextField variableNameField = new JTextField();
        variableNameField.setPreferredSize(new Dimension(220, 30));

        JLabel variableValueLabel = new JLabel("Variable value");
        variableValueLabel.setPreferredSize(new Dimension(220, 25));
        JTextField variableValueField = new JTextField();
        variableValueField.setPreferredSize(new Dimension(220, 30));

        JComboBox variableCombo = new JComboBox();

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createVariableWindow.setVisible(false);
                createVariableWindow.getContentPane().removeAll();
            }
        });
        JButton createButton = new JButton("Create/Update variable");
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                errorMessage.setText("");
                String variableName = variableNameField.getText().replaceAll("[^\\w+]", "");
                String variableValue = variableValueField.getText();
                if (variableName.length() < 1) {
                    errorMessage.setText("Invalid variable name. Use a-zA-Z_0-9 for variable names");
                    return;
                }
                if (variableValue.length() < 1) {
                    errorMessage.setText("Your variable value cannot be blank");
                    return;
                }
                HackvertorExtension.globalVariables.put(variableName, variableValue);
                variableCombo.removeAllItems();
                for (String variable : HackvertorExtension.globalVariables.keySet()) {
                    variableCombo.addItem(variable);
                }
                saveGlobalVariables();
            }
        });
        if (!HackvertorExtension.isNativeTheme && !HackvertorExtension.isDarkTheme) {
            createButton.setBackground(Color.decode("#005a70"));
            createButton.setForeground(Color.white);
            closeButton.setBackground(Color.decode("#005a70"));
            closeButton.setForeground(Color.white);
        }

        JLabel tagLabel = new JLabel("Variable");
        tagLabel.setPreferredSize(new Dimension(50, 25));
        variableCombo.setPreferredSize(new Dimension(200, 25));
        createVariablePanel.add(tagLabel);
        createVariablePanel.add(variableCombo);
        for (String variable : HackvertorExtension.globalVariables.keySet()) {
            variableCombo.addItem(variable);
        }
        JButton copyButton = new JButton("copy");
        copyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (variableCombo.getSelectedIndex() == -1) {
                    return;
                }
                String key = variableCombo.getSelectedItem().toString();
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection variableTag = new StringSelection("<@get_"+key+"/>");
                clipboard.setContents(variableTag, null);
            }
        });
        JButton editButton = new JButton("Edit");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (variableCombo.getSelectedIndex() == -1) {
                    return;
                }
                String key = variableCombo.getSelectedItem().toString();
                variableNameField.setText(key);
                variableValueField.setText(HackvertorExtension.globalVariables.get(key));
            }
        });
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (variableCombo.getSelectedIndex() == -1) {
                    return;
                }
                HackvertorExtension.globalVariables.remove(variableCombo.getSelectedItem().toString());
                variableCombo.removeAllItems();
                for (String variable : HackvertorExtension.globalVariables.keySet()) {
                    variableCombo.addItem(variable);
                }
                saveGlobalVariables();
            }
        });
        createVariablePanel.add(copyButton);
        createVariablePanel.add(editButton);
        createVariablePanel.add(deleteButton);

        Container pane = createVariableWindow.getContentPane();
        createVariablePanel.add(errorMessage);
        createVariablePanel.add(variableLabel);
        createVariablePanel.add(variableNameField);
        createVariablePanel.add(variableValueLabel);
        createVariablePanel.add(variableValueField);
        createVariablePanel.add(closeButton);
        createVariablePanel.add(createButton);
        pane.add(createVariablePanel);
        createVariableWindow.pack();
        createVariableWindow.setLocationRelativeTo(null);
        createVariableWindow.setVisible(true);
    }

    public static void saveGlobalVariables() {
        JSONObject json = new JSONObject(HackvertorExtension.globalVariables);
        HackvertorExtension.callbacks.saveExtensionSetting("globalVariables", json.toString());
    }

    public static void loadGlobalVariables() {
        String json = HackvertorExtension.callbacks.loadExtensionSetting("globalVariables");
        if (json != null && json.length() > 0) {
            try {
                JSONObject jsonObject = new JSONObject(json);
                Iterator<String> keys = jsonObject.keys();
                while(keys.hasNext()) {
                    String key = keys.next();
                    HackvertorExtension.globalVariables.put(key, jsonObject.get(key).toString());
                }
            } catch (JSONException e) {
                HackvertorExtension.alert("Failed to load global variables");
            }
        }
    }
}
