package burp.hv.tags;

import burp.hv.HackvertorExtension;
import burp.hv.ai.AI;
import burp.hv.ai.CodeConversion;
import burp.hv.ai.SummariseCode;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.ui.HackvertorInput;
import burp.hv.utils.GridbagUtils;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.hv.Convertors.*;
import static burp.hv.HackvertorExtension.*;
import static burp.hv.HackvertorExtension.tagCodeExecutionKey;
import static burp.hv.ai.AI.featureMessage;
import static java.awt.GridBagConstraints.CENTER;

public class CustomTags {
    public static String argumentsRegex = "(?:0x[a-fA-F0-9]+|\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";

    public static Tag generateCustomTag(JSONObject customTag) {
        int numberOfArgs = 0;
        if (customTag.has("numberOfArgs")) {
            numberOfArgs = customTag.getInt("numberOfArgs");
        }
        String argumentsTooltip = "";
        if (numberOfArgs == 1) {
            argumentsTooltip = "(" + (customTag.getString("argument1Type").equals("String") ? "String " + customTag.getString("argument1") + "," : "int " + customTag.getString("argument1") + ",") + "+String codeExecuteKey)";
        } else if (numberOfArgs == 2) {
            argumentsTooltip = "(" + (customTag.getString("argument1Type").equals("String") ? "String " + customTag.getString("argument1") + "," : "int " + customTag.getString("argument1") + ",") + (customTag.getString("argument2Type").equals("String") ? "String " + customTag.getString("argument2") + "," : "int " + customTag.getString("argument2") + ",") + "String codeExecuteKey)";
        } else {
            argumentsTooltip = "(String codeExecuteKey)";
        }
        Tag tag = new Tag(Tag.Category.Custom, customTag.getString("tagName"), true, customTag.getString("language") + argumentsTooltip);
        if (numberOfArgs == 0) {
            tag.argument1 = new TagArgument("string", HackvertorExtension.tagCodeExecutionKey);
        }
        if (numberOfArgs == 1) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            tag.argument2 = new TagArgument("string", HackvertorExtension.tagCodeExecutionKey);
        }
        if (numberOfArgs == 2) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            String argument2Type = customTag.getString("argument2Type");
            String argument2Default = customTag.getString("argument2Default");
            if (argument2Type.equals("String")) {
                tag.argument2 = new TagArgument("string", argument2Default);
            } else {
                tag.argument2 = new TagArgument("int", argument2Default);
            }
            tag.argument3 = new TagArgument("string", HackvertorExtension.tagCodeExecutionKey);
        }
        return tag;
    }

    public static void showCreateEditTagDialog(boolean edit, String editTagName) {
        String defaultAiInstructions = "Decode the JWT token:";
        JPanel createTagPanel = new JPanel(new GridBagLayout());
        createTagPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        JFrame createTagWindow = Utils.getHackvertorWindowInstance();
        createTagWindow.getContentPane().removeAll();
        createTagWindow.getContentPane().setLayout(new BorderLayout());
        JSONObject customTag = null;
        if (edit) {
            createTagWindow.setTitle("Edit custom tag");
        } else {
            createTagWindow.setTitle("Create custom tag");
        }

        if (edit) {
            for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
                customTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
                if (customTag.getString("tagName").equals(editTagName)) {
                    break;
                }
            }
        }
        createTagWindow.setResizable(true);
        createTagWindow.setPreferredSize(new Dimension(800, 600));
        createTagPanel.setPreferredSize(new Dimension(800, 600));
        JLabel tagLabel = new JLabel("Tag name");
        JTextField tagNameField = new JTextField();
        if (edit && customTag != null && customTag.has("tagName")) {
            tagNameField.setText(customTag.getString("tagName"));
            tagNameField.setEditable(false);
        }
        createTagPanel.add(tagLabel, GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        createTagPanel.add(tagNameField, GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        JLabel languageLabel = new JLabel("Select language");
        HackvertorInput codeArea = new HackvertorInput();
        JScrollPane codeScroll = new JScrollPane(codeArea);
        JComboBox<String> argument1Combo = new JComboBox<String>();
        argument1Combo.addItem("None");
        argument1Combo.addItem("String");
        argument1Combo.addItem("Number");
        JComboBox<String> languageCombo = new JComboBox<String>();
        JTextField argument1NameField = new JTextField();
        JTextField argument1DefaultValueField = new JTextField();
        languageCombo.addItem("AI");
        languageCombo.addItem("JavaScript");
        languageCombo.addItem("Python");
        languageCombo.addItem("Java");
        languageCombo.addItem("Groovy");
        final boolean[] hasEditedCode = {false};
        codeArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                hasEditedCode[0] = true;
            }
        });
        languageCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = languageCombo.getSelectedIndex();
                String comment = "//";
                if(index == 2) {
                    comment = "#";
                }
                String code = "output = input\n";
                code += comment + "output = convert(\"<@base64>\"+input+\"</@base64>\")\n";
                code += comment + "output = convert(\"<@customTag('\"+executionKey+\"')>\"+input+\"</@customTag>\")";
                if(index == 0) {
                    code = defaultAiInstructions;
                    if(!edit) {
                        argument1Combo.setSelectedIndex(1);
                        argument1NameField.setText("temperature");
                        argument1DefaultValueField.setText("1.0");
                    }
                } else {
                    if(!edit) {
                        argument1Combo.setSelectedIndex(0);
                        argument1NameField.setText("");
                        argument1DefaultValueField.setText("");
                    }
                }
                if(!hasEditedCode[0]) {
                    codeArea.setText(code);
                }
            }
        });
        if (edit && customTag != null && customTag.has("language")) {
            if (customTag.getString("language").equals("AI")) {
                languageCombo.setSelectedIndex(0);
            } else if (customTag.getString("language").equals("JavaScript")) {
                languageCombo.setSelectedIndex(1);
            } else if (customTag.getString("language").equals("Python")) {
                languageCombo.setSelectedIndex(2);
            } else if (customTag.getString("language").equals("Java")) {
                languageCombo.setSelectedIndex(3);
            } else if (customTag.getString("language").equals("Groovy")) {
                languageCombo.setSelectedIndex(4);
            }
        }

        if(!edit) {
            if (!AI.isAiSupported()) {
                languageCombo.setSelectedIndex(1);
            } else {
                languageCombo.setSelectedIndex(0);
            }
        }

        if (edit && customTag != null && customTag.has("code")) {
            codeArea.setText(customTag.getString("code"));
        }

        Container pane = createTagWindow.getContentPane();
        createTagPanel.add(languageLabel, GridbagUtils.createConstraints(0, 1, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        createTagPanel.add(languageCombo, GridbagUtils.createConstraints(1, 1, 1, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        JLabel argument1Label = new JLabel("Argument1");
        if (edit && customTag != null && customTag.has("argument1Type")) {
            if (customTag.getString("argument1Type").equals("String")) {
                argument1Combo.setSelectedIndex(1);
            } else if (customTag.getString("argument1Type").equals("Number")) {
                argument1Combo.setSelectedIndex(2);
            }
        }
        JLabel argument1NameLabel = new JLabel("Param Name");
        if (edit && customTag != null && customTag.has("argument1")) {
            argument1NameField.setText(customTag.getString("argument1"));
        }
        JLabel argument1DefaultLabel = new JLabel("Default value");
        if (edit && customTag != null && customTag.has("argument1Default")) {
            argument1DefaultValueField.setText(customTag.getString("argument1Default"));
        }

        JPanel argument1Panel = new JPanel();
        argument1Panel.setBorder(new EmptyBorder(0, 0, 0, 10));
        argument1Panel.setPreferredSize(new Dimension(400, 300));
        argument1Panel.setLayout(new GridBagLayout());
        argument1Panel.add(argument1Label, GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument1Panel.add(argument1Combo, GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument1Panel.add(argument1NameLabel, GridbagUtils.createConstraints(0, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument1Panel.add(argument1NameField, GridbagUtils.createConstraints(1, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument1Panel.add(argument1DefaultLabel, GridbagUtils.createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument1Panel.add(argument1DefaultValueField, GridbagUtils.createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        createTagPanel.add(argument1Panel, GridbagUtils.createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));

        JLabel argument2NameLabel = new JLabel("Param Name");
        JLabel argument2Label = new JLabel("Argument2");
        JComboBox<String> argument2Combo = new JComboBox<String>();
        argument2Combo.addItem("None");
        argument2Combo.addItem("String");
        argument2Combo.addItem("Number");
        if (edit && customTag != null && customTag.has("argument2Type")) {
            if (customTag.getString("argument2Type").equals("String")) {
                argument2Combo.setSelectedIndex(1);
            } else if (customTag.getString("argument2Type").equals("Number")) {
                argument2Combo.setSelectedIndex(2);
            }
        }
        JTextField argument2NameField = new JTextField();
        if (edit && customTag != null && customTag.has("argument2")) {
            argument2NameField.setText(customTag.getString("argument2"));
        }
        JLabel argument2DefaultLabel = new JLabel("Default value");
        JTextField argument2DefaultValueField = new JTextField();
        if (edit && customTag != null && customTag.has("argument2Default")) {
            argument2DefaultValueField.setText(customTag.getString("argument2Default"));
        }
        JPanel argument2Panel = new JPanel();
        argument2Panel.setPreferredSize(new Dimension(400, 300));
        argument2Panel.setLayout(new GridBagLayout());
        argument2Panel.add(argument2Label, GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument2Panel.add(argument2Combo, GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument2Panel.add(argument2NameLabel, GridbagUtils.createConstraints(0, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument2Panel.add(argument2NameField, GridbagUtils.createConstraints(1, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument2Panel.add(argument2DefaultLabel, GridbagUtils.createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        argument2Panel.add(argument2DefaultValueField, GridbagUtils.createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        createTagPanel.add(argument2Panel, GridbagUtils.createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5, CENTER));
        JLabel convertLabel = new JLabel("You can now convert Hackvertor tags inside customTags!");
        JLabel codeLabel = new JLabel("Code (if you end the code with .js/.py/.java/.groovy it will read a file)");
        createTagPanel.add(convertLabel, GridbagUtils.createConstraints(0, 3, 2, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        createTagPanel.add(codeLabel, GridbagUtils.createConstraints(0, 4, 2, GridBagConstraints.BOTH, 0, 0, 5, 5, CENTER));
        createTagPanel.add(codeScroll, GridbagUtils.createConstraints(0, 5, 2, GridBagConstraints.BOTH, 1, 1, 5, 5, CENTER));
        int y = 6;
        if(customTag != null && customTag.has("summary")) {
            JTextArea summary = new JTextArea(customTag.getString("summary"));
            summary.setPreferredSize(new Dimension(800, 200));
            summary.setLineWrap(true);
            summary.setWrapStyleWord(true);
            createTagPanel.add(summary, GridbagUtils.createConstraints(0, y, 2, GridBagConstraints.HORIZONTAL, 1, 0, 0, 0, CENTER));
            y++;
        }
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createTagWindow.setVisible(false);
                createTagWindow.getContentPane().removeAll();
                if(edit) {
                    CustomTags.showListTagsDialog();
                }
            }
        });
        JLabel errorMessage = new JLabel();
        errorMessage.setForeground(Color.red);
        JButton createButton = new JButton("Create tag");
        JButton exportButton = new JButton("Export to tag store");
        JSONObject finalCustomTag = customTag;
        exportButton.addActionListener(e -> {
            loadCustomTags();
            for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
                JSONObject savedCustomTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
                if (finalCustomTag.getString("tagName").equals(savedCustomTag.getString("tagName"))) {
                    JSONObject customTagCopy = new JSONObject(savedCustomTag, JSONObject.getNames(savedCustomTag));
                    customTagCopy.remove("code");
                    customTagCopy.put("tagName", customTagCopy.get("tagName").toString().replaceFirst("^_",""));
                    String author = JOptionPane.showInputDialog(null, "Enter your github username", "");
                    if(author == null || author.isEmpty()) {
                        return;
                    }
                    String description = JOptionPane.showInputDialog(null, "Enter a description of your tag", "");
                    if(description.isEmpty()) {
                        return;
                    }
                    customTagCopy.put("author",author);
                    customTagCopy.put("description",description);
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    StringSelection customTagCopyJSON = new StringSelection(customTagCopy.toString(3));
                    clipboard.setContents(customTagCopyJSON, null);
                    HackvertorExtension.alert("Copied JSON data to clipboard.");
                    Utils.openUrl("https://github.com/hackvertor/hackvertor/blob/master/tag-store/README.md");
                    return;
                }
            }
            HackvertorExtension.alert("Unable to find tag");
        });
        if (edit) {
            createButton.setText("Update tag");
        }
        JButton testButton = new JButton("Test tag");
        testButton.addActionListener(e -> {
            String tagName = TagUtils.sanitizeTagName(tagNameField.getText());
            String language = languageCombo.getSelectedItem().toString();
            String code = codeArea.getText();
            String argument1 = argument1NameField.getText();
            String argument1DefaultValue = argument1DefaultValueField.getText();
            String argument2 = argument2NameField.getText();
            String argument2DefaultValue = argument2DefaultValueField.getText();
            String argument1Type = argument1Combo.getSelectedItem().toString();
            String argument2Type = argument2Combo.getSelectedItem().toString();
            if(language.equalsIgnoreCase("AI") && !AI.isAiSupported()) {
                alert(featureMessage);
                return;
            }
            int numberOfArgs = 0;
            if (argument1Combo.getSelectedIndex() > 0) {
                numberOfArgs++;
            }
            if (argument2Combo.getSelectedIndex() > 0) {
                numberOfArgs++;
            }
            String input = JOptionPane.showInputDialog(null, "Enter input for your tag", "test");
            JSONObject tag = new JSONObject();
            tag.put("tagName", "_" + tagName);
            tag.put("language", language);
            if (numberOfArgs == 1) {
                tag.put("argument1", argument1);
                tag.put("argument1Type", argument1Type);
                tag.put("argument1Default", argument1DefaultValue);
            }
            if (numberOfArgs == 2) {
                tag.put("argument1", argument1);
                tag.put("argument1Type", argument1Type);
                tag.put("argument1Default", argument1DefaultValue);
                tag.put("argument2", argument2);
                tag.put("argument2Type", argument2Type);
                tag.put("argument2Default", argument2DefaultValue);
            }
            tag.put("numberOfArgs", numberOfArgs);
            tag.put("code", code);
            JSONObject customTagOptions = new JSONObject();
            customTagOptions.put("customTag", tag);
            ArrayList<String> args = new ArrayList<>();
            if (numberOfArgs == 0) {
                customTagOptions = null;
            } else if (numberOfArgs == 1) {
                if (argument1Type.equals("String")) {
                    customTagOptions.put("param1", argument1DefaultValue);
                } else if (argument1Type.equals("Number")) {
                    args.add(argument1DefaultValue);
                    customTagOptions.put("param1", getInt(args, 0));
                }
            } else if (numberOfArgs == 2) {
                int pos = 0;
                if (argument1Type.equals("String")) {
                    customTagOptions.put("param1", argument1DefaultValue);
                } else if (argument1Type.equals("Number")) {
                    args.add(argument1DefaultValue);
                    customTagOptions.put("param1", getInt(args, 0));
                    pos++;
                }
                if (argument2Type.equals("String")) {
                    customTagOptions.put("param2", argument2DefaultValue);
                } else if (argument2Type.equals("Number")) {
                    args.add(argument2DefaultValue);
                    customTagOptions.put("param2", getInt(args, pos));
                }
            }

            try {
                JSONObject finalCustomTagOptions = customTagOptions;
                HackvertorExtension.executorService.submit(() -> {
                    String output = "";
                    if (language.equals("AI")) {
                        output = ai_tag(new HashMap<>(), input, code, HackvertorExtension.tagCodeExecutionKey, finalCustomTagOptions, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor, 1.0, false);
                    } else if (language.equals("JavaScript")) {
                        output = javascript(new HashMap<>(), input, code, HackvertorExtension.tagCodeExecutionKey, finalCustomTagOptions, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                    } else if(language.equals("Python")){
                        output = python(new HashMap<>(), input, code, HackvertorExtension.tagCodeExecutionKey, finalCustomTagOptions, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                    } else if(language.equals("Java")){
                        output = java(new HashMap<>(), input, code, HackvertorExtension.tagCodeExecutionKey, finalCustomTagOptions, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                    } else if(language.equals("Groovy")){
                        output = groovy(new HashMap<>(), input, code, HackvertorExtension.tagCodeExecutionKey, finalCustomTagOptions, HackvertorExtension.hackvertor.getCustomTags(), HackvertorExtension.hackvertor);
                    }
                    HackvertorExtension.alert("Output from tag:" + output);
                });

            }catch (Throwable ex){
                alert(ex.toString());
                throw new RuntimeException(ex);
            }
        });
        createButton.addActionListener(e -> {
            createButton.setText("Loading...");
            ExecutorService service = Executors.newSingleThreadExecutor();
            try (Closeable close = service::shutdown) {
                service.submit(() -> {
                    String tagName = TagUtils.sanitizeTagName(tagNameField.getText());
                    String language = languageCombo.getSelectedItem().toString();
                    String code = codeArea.getText();
                    String argument1 = argument1NameField.getText();
                    String argument1DefaultValue = argument1DefaultValueField.getText();
                    String argument2 = argument2NameField.getText();
                    String argument2DefaultValue = argument2DefaultValueField.getText();

                    if(!AI.isAiSupported() && language.equals("AI")) {
                        alert(featureMessage);
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }

                    int numberOfArgs = 0;
                    if (!TagUtils.validateTagName(tagName)) {
                        errorMessage.setText("Invalid tag name. Use a-zA-Z_0-9 for tag names");
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (!TagUtils.validateCode(code)) {
                        errorMessage.setText("Please enter some code. Code cannot be blank.");
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument1Combo.getSelectedIndex() > 0 && !TagUtils.validateParam(argument1)) {
                        errorMessage.setText("Invalid param name. For argument1. Use " + TagUtils.paramRegex);
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument1Combo.getSelectedItem().equals("Number") && !TagUtils.validateTagParamNumber(argument1DefaultValue)) {
                        errorMessage.setText("Invalid default value for argument1. Use " + TagUtils.numberRegex);
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument2Combo.getSelectedIndex() > 0 && !TagUtils.validateParam(argument2)) {
                        errorMessage.setText("Invalid param name for argument2. Use " + TagUtils.paramRegex);
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument2Combo.getSelectedIndex() > 0 && argument1Combo.getSelectedIndex() == 0) {
                        errorMessage.setText("You have selected two arguments but not defined the first.");
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument2Combo.getSelectedItem().toString().equals("Number") && !TagUtils.validateTagParamNumber(argument2DefaultValue)) {
                        errorMessage.setText("Invalid default value for argument2. Use " + TagUtils.numberRegex);
                        createButton.setText(edit ? "Update tag" : "Create tag");
                        return;
                    }
                    if (argument1Combo.getSelectedIndex() > 0) {
                        numberOfArgs++;
                    }
                    if (argument2Combo.getSelectedIndex() > 0) {
                        numberOfArgs++;
                    }
                    if (edit) {
                        updateCustomTag(tagName, language, code, argument1, argument1Combo.getSelectedItem().toString(), argument1DefaultValue, argument2, argument2Combo.getSelectedItem().toString(), argument2DefaultValue, numberOfArgs);
                    } else {
                        if(!createCustomTag(tagName, language, code, argument1, argument1Combo.getSelectedItem().toString(), argument1DefaultValue, argument2, argument2Combo.getSelectedItem().toString(), argument2DefaultValue, numberOfArgs)) {
                            errorMessage.setText("Unable to create custom tag. It already exists.");
                            createButton.setText( "Create tag");
                            return;
                        }
                    }
                    createButton.setText(edit ? "Update tag" : "Create tag");
                    HackvertorExtension.extensionPanel.refresh();
                    createTagWindow.setVisible(false);
                    createTagWindow.getContentPane().removeAll();
                });
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            } finally {
                service.shutdown();
            }
        });
        JPanel buttonsPanel = new JPanel(new GridBagLayout());
        buttonsPanel.add(cancelButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        if(edit) {
            buttonsPanel.add(exportButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        }

        try {
            boolean allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            if(AI.isAiSupported() && allowAiToGenerateCode) {
                JButton generateCodeButton = new JButton("Use AI to generate code");
                generateCodeButton.setEnabled(AI.isAiSupported());
                generateCodeButton.addActionListener(e->{
                    generateCodeButton.setText("Loading...");
                    ExecutorService service = Executors.newSingleThreadExecutor();
                    try (Closeable close = service::shutdown) {
                        service.submit(() -> {
                            try {
                                String prompt = codeArea.getText();
                                String language = languageCombo.getSelectedItem().toString();
                                JSONObject aiPrompt = new JSONObject();
                                if(language.equals("AI")) {
                                    HackvertorExtension.alert("You need to select a programming language to generate code");
                                    generateCodeButton.setText("Use AI to generate code");
                                    return;
                                }
                                if (tagNameField.getText().isEmpty() || prompt.isEmpty()) {
                                    HackvertorExtension.alert("In order to generate code you need to supply a prompt in the code box and a tag name");
                                    generateCodeButton.setText("Use AI to generate code");
                                    return;
                                }
                                aiPrompt.put("name", tagNameField.getText());
                                aiPrompt.put("prompt", prompt);
                                String generatedCode = null;
                                String additionalInstructions = "";
                                String argument1 = argument1NameField.getText();
                                String argument1DefaultValue = argument1DefaultValueField.getText();
                                String argument2 = argument2NameField.getText();
                                String argument2DefaultValue = argument2DefaultValueField.getText();
                                if (!argument1.isEmpty() && !argument1DefaultValue.isEmpty()) {
                                    additionalInstructions += "The user has already defined a variable called " + argument1 + " with a value of " + argument1DefaultValue + ". This should be passed as an argument to your function.";
                                }
                                if (!argument2.isEmpty() && !argument2DefaultValue.isEmpty()) {
                                    additionalInstructions += "The user has defined a second variable called " + argument2 + " with a value of " + argument2DefaultValue + ". This should be passed as an argument to your function.";
                                }

                                if (!argument1.isEmpty() && !argument1DefaultValue.isEmpty() && !argument2.isEmpty() && !argument2DefaultValue.isEmpty()) {
                                    additionalInstructions += "Your function should always have 3 arguments: input, " + argument1 + " and " + argument2;
                                } else if (!argument1.isEmpty() && !argument1DefaultValue.isEmpty()) {
                                    additionalInstructions += "Your function should always have 2 arguments: input and " + argument1;
                                }

                                if (language.equals("Python")) {
                                    additionalInstructions += "The code generated should run on Python 2.7\n";
                                } else if (language.equals("Java")) {
                                    additionalInstructions += "DO NOT USE ANY CLASSES JUST DECLARE PUBLIC FUNCTIONS.\n";
                                } else if (language.equals("JavaScript")) {
                                    additionalInstructions += "This code should work in the browser. Do not use any node functions or libraries.\n";
                                }
                                String variables = "\noutput = " + aiPrompt.getString("name") + "(input";
                                if (!argument1.isEmpty() && !argument1DefaultValue.isEmpty()) {
                                    variables += "," + argument1;
                                }
                                if (!argument2.isEmpty() && !argument2DefaultValue.isEmpty()) {
                                    variables += "," + argument2;
                                }
                                variables += ")";
                                generatedCode = CodeConversion.promptToCode(language, aiPrompt, additionalInstructions) + variables;
                                codeArea.setText(generatedCode);
                                hasEditedCode[0] = true;
                            } catch(Throwable ex) {
                                alert(ex.toString());
                                throw new RuntimeException(ex);
                            } finally {
                                generateCodeButton.setText("Use AI to generate code");
                            }
                        });
                    } catch (Throwable ex) {
                        alert(ex.toString());
                        throw new RuntimeException(ex);
                    } finally {
                        service.shutdown();
                        generateCodeButton.setText("Use AI to generate code");
                    }

                });
                buttonsPanel.add(generateCodeButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(2, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
            } else {
                JButton generateCodeButton = new JButton("Use AI to generate code");
                generateCodeButton.addActionListener((e) -> {
                    if(AI.isAiSupported() && !allowAiToGenerateCode) {
                        alert("You have not allowed the AI to generate code in settings.");
                    } else {
                        alert(featureMessage);
                    }
                });
                buttonsPanel.add(generateCodeButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(2, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
            }
        } catch (UnregisteredSettingException e) {
            throw new RuntimeException(e);
        } catch (InvalidTypeSettingException e) {
            throw new RuntimeException(e);
        }

        buttonsPanel.add(testButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(3, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        buttonsPanel.add(createButton, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(4, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        createTagPanel.add(buttonsPanel, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(0, y, 2, GridBagConstraints.NONE, 1, 0, 5, 5, CENTER), 2, 2, 2, 2));
        y++;
        createTagPanel.add(errorMessage, GridbagUtils.addMarginToGbc(GridbagUtils.createConstraints(0, y, 3, GridBagConstraints.NONE, 0, 0, 5, 5, CENTER), 2, 2, 2, 2));
        pane.add(createTagPanel);
        createTagWindow.pack();
        createTagWindow.setLocationRelativeTo(null);
        createTagWindow.setVisible(true);
    }

    public static void showListTagsDialog() {
        JPanel listTagsPanel = new JPanel();
        JFrame listTagsWindow = Utils.getHackvertorWindowInstance();
        listTagsWindow.getContentPane().removeAll();
        listTagsWindow.getContentPane().setLayout(new BorderLayout());
        listTagsWindow.setTitle("List custom tags");
        listTagsWindow.setResizable(false);
        listTagsWindow.setPreferredSize(new Dimension(500, 150));
        listTagsWindow.setVisible(true);
        JLabel tagLabel = new JLabel("Tag");
        tagLabel.setPreferredSize(new Dimension(50, 25));
        JComboBox tagCombo = new JComboBox();
        tagCombo.setPreferredSize(new Dimension(200, 25));
        listTagsPanel.add(tagLabel);
        listTagsPanel.add(tagCombo);
        ArrayList<String> tagList = new ArrayList<>();
        for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
            tagList.add(customTag.getString("tagName"));
        }
        Collections.sort(tagList);
        for(String tag : tagList) {
            tagCombo.addItem(tag);
        }
        JButton editButton = new JButton("Edit tag");
        editButton.addActionListener(e -> {
            if (tagCombo.getSelectedIndex() == -1) {
                return;
            }
            listTagsWindow.setVisible(false);
            listTagsWindow.getContentPane().removeAll();
            showCreateEditTagDialog( true, tagCombo.getSelectedItem().toString());
        });
        JButton deleteButton = new JButton("Delete tag");
        JButton loadButton = new JButton("Load tags from clipboard");
        JButton exportButton = new JButton("Export all my tags to clipboard");
        JButton loadFromJsonButton = new JButton("Load from JSON file");
        JButton exportToJsonButton = new JButton("Export all my tags to JSON file");
        exportToJsonButton.addActionListener(e -> {
            String customTagsJSON = HackvertorExtension.hackvertor.getCustomTags().toString();
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new FileFilter() {
                @Override
                public boolean accept(File f) {
                    return f.getPath().endsWith(".json") || f.isDirectory();
                }

                @Override
                public String getDescription() {
                    return "JSON only";
                }
            });
            fileChooser.setDialogTitle("Specify a JSON file to save");
            int userSelection = fileChooser.showSaveDialog(listTagsWindow);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                if(fileToSave != null && fileToSave.getAbsolutePath().endsWith(".json")) {
                    BufferedWriter writer = null;
                    try {
                        writer = new BufferedWriter(new FileWriter(fileToSave.getAbsolutePath()));
                    } catch (IOException ex) {
                        HackvertorExtension.alert("Unable to open file to write:" + ex);
                        return;
                    }
                    try {
                        writer.write(customTagsJSON);
                    } catch (IOException ex) {
                        HackvertorExtension.alert("Failed to write file:" + ex);
                        return;
                    }
                    try {
                        writer.close();
                    } catch (IOException ex) {
                        HackvertorExtension.alert("Failed to close file:" + ex);
                    }
                }
            }
        });
        loadFromJsonButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new FileFilter() {
                @Override
                public boolean accept(File f) {
                    return f.getPath().endsWith(".json") || f.isDirectory();
                }

                @Override
                public String getDescription() {
                    return "JSON only";
                }
            });
            fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
            int result = fileChooser.showOpenDialog(listTagsWindow);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if(selectedFile != null && selectedFile.getAbsolutePath().endsWith(".json")) {
                    try {
                        String json = FileUtils.readFileToString(selectedFile, "UTF-8");
                        if (json != null && !json.isEmpty()) {
                            try {
                                JSONArray tags = new JSONArray(json);
                                for(int i=0;i<tags.length();i++) {
                                    JSONObject tag = tags.getJSONObject(i);
                                    if (!TagUtils.validateCode(tag.getString("code"))) {
                                        HackvertorExtension.alert("Invalid code unable to install tag. Code cannot be blank.");
                                        return;
                                    }
                                    String argument1 = null;
                                    String argument1Type = null;
                                    String argument1Default = null;
                                    String argument2 = null;
                                    String argument2Type = null;
                                    String argument2Default = null;
                                    int numberOfArgs = tag.getInt("numberOfArgs");
                                    if(numberOfArgs > 0) {
                                        argument1 = tag.getString("argument1");
                                        argument1Type = tag.getString("argument1Type");
                                        argument1Default = tag.getString("argument1Default");
                                        if (!TagUtils.validateParam(argument1)) {
                                            HackvertorExtension.alert("Invalid param name. For argument1. Use " + TagUtils.paramRegex);
                                            return;
                                        }
                                        if (argument1Type.equals("Number") && !TagUtils.validateTagParamNumber(argument1Default)) {
                                            HackvertorExtension.alert("Invalid default value for argument1. Use " + TagUtils.numberRegex);
                                            return;
                                        }
                                        if(numberOfArgs == 2) {
                                            argument2 = tag.getString("argument2");
                                            argument2Type = tag.getString("argument2Type");
                                            argument2Default = tag.getString("argument2Default");

                                            if (!TagUtils.validateParam(argument2)) {
                                                HackvertorExtension.alert("Invalid param name for argument2. Use " + TagUtils.paramRegex);
                                                return;
                                            }
                                            if (argument2Type.equals("Number") && !TagUtils.validateTagParamNumber(argument2Default)) {
                                                HackvertorExtension.alert("Invalid default value for argument2. Use " + TagUtils.numberRegex);
                                                return;
                                            }
                                        }
                                    }
                                }
                                HackvertorExtension.hackvertor.setCustomTags(tags);
                                HackvertorExtension.alert("All your tags have been replaced from the file");
                                saveCustomTags();
                                listTagsWindow.setVisible(false);
                                listTagsWindow.getContentPane().removeAll();
                                showListTagsDialog();
                            } catch (JSONException ex) {
                                HackvertorExtension.alert("Invalid JSON: " + ex);
                            }
                        }
                    } catch (IOException ex) {
                        HackvertorExtension.alert("Unable to load JSON: " + ex);
                    }

                }
            }
        });
        exportButton.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection customTagsJSON = new StringSelection(HackvertorExtension.hackvertor.getCustomTags().toString());
            clipboard.setContents(customTagsJSON, null);
        });
        loadButton.addActionListener(e -> {
            int input = JOptionPane.showConfirmDialog(null, "Are you sure you sure you want to load all tags from the clipboard? This will replace your existing tags");
            if (input != 0) {
                return;
            }
            try {
                String tagsJSON = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
                if (tagsJSON != null && !tagsJSON.isEmpty()) {
                    try {
                        JSONArray tags = new JSONArray(tagsJSON);
                        HackvertorExtension.hackvertor.setCustomTags(tags);
                        HackvertorExtension.alert("All your tags have been replaced from the clipboard");
                        saveCustomTags();
                        listTagsWindow.setVisible(false);
                        listTagsWindow.getContentPane().removeAll();
                        showListTagsDialog();
                    } catch (JSONException ex) {
                        HackvertorExtension.alert("Invalid JSON");
                    }
                }
            } catch (UnsupportedFlavorException unsupportedFlavorException) {
                HackvertorExtension.alert("Invalid JSON");
            } catch (IOException ioException) {
                ioException.printStackTrace();
                HackvertorExtension.alert("Invalid JSON");
            }
        });
        deleteButton.addActionListener(e -> {
            if (tagCombo.getSelectedIndex() == -1) {
                return;
            }
            int input = JOptionPane.showConfirmDialog(null, "Are you sure you want to delete this tag?");
            if (input != 0) {
                return;
            }
            for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
                JSONObject customTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
                if (tagCombo.getSelectedItem().toString().equals(customTag.getString("tagName"))) {
                    HackvertorExtension.hackvertor.getCustomTags().remove(i);
                    tagCombo.removeItemAt(tagCombo.getSelectedIndex());
                    saveCustomTags();
                    break;
                }
            }
            HackvertorExtension.extensionPanel.refresh();
        });
        listTagsPanel.add(editButton);
        listTagsPanel.add(deleteButton);
        listTagsPanel.add(loadButton);
        listTagsPanel.add(exportButton);
        listTagsPanel.add(loadFromJsonButton);
        listTagsPanel.add(exportToJsonButton);
        listTagsWindow.add(listTagsPanel);
        listTagsWindow.pack();
        listTagsWindow.setLocationRelativeTo(null);
        listTagsWindow.setVisible(true);
    }

    public static void loadCustomTags() {
        String json = HackvertorExtension.callbacks.loadExtensionSetting("customTags");
        if (json != null && json.length() > 0) {
            try {
                HackvertorExtension.hackvertor.setCustomTags(new JSONArray(json));
            } catch (JSONException e) {
                HackvertorExtension.alert("Failed to load custom tags");
            }
        }
    }

    public static void saveCustomTags() {
        HackvertorExtension.callbacks.saveExtensionSetting("customTags", HackvertorExtension.hackvertor.getCustomTags().toString());
    }

    public static void updateCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
        JSONObject tag = new JSONObject();
        tag.put("tagName", tagName);
        tag.put("language", language);
        boolean hasCodeChanged = false;
        try {
            for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
                JSONObject customTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
                if (tagName.equals(customTag.getString("tagName"))) {
                    if(!customTag.getString("code").equals(code)) {
                        hasCodeChanged = true;
                    }
                    break;
                }
            }

            if(hasCodeChanged && HackvertorExtension.generalSettings.getBoolean("allowAiToSummariseCode") && !language.equals("AI")) {
                if(AI.isAiSupported()) {
                    String summary = SummariseCode.getSummary(language, code);
                    tag.put("summary", summary);
                }
            }
        } catch (Exception e) {
            callbacks.printError(e.toString());
        }

        if (numberOfArgs == 1) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
        }
        if (numberOfArgs == 2) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
            tag.put("argument2", argument2);
            tag.put("argument2Type", argument2Type);
            tag.put("argument2Default", argument2DefaultValue);
        }
        tag.put("numberOfArgs", numberOfArgs);
        tag.put("code", code);
        for (int i = 0; i < HackvertorExtension.hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) HackvertorExtension.hackvertor.getCustomTags().get(i);
            if (tagName.equals(customTag.getString("tagName"))) {
                HackvertorExtension.hackvertor.getCustomTags().put(i, tag);
                saveCustomTags();
                break;
            }
        }
        saveCustomTags();
    }

    public static boolean createCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
        if (HackvertorExtension.hackvertor.hasCustomTag(tagName)) {
           return false;
        }
        JSONObject tag = new JSONObject();
        tag.put("tagName", "_" + tagName);
        tag.put("language", language);

        try {
            if(HackvertorExtension.generalSettings.getBoolean("allowAiToSummariseCode") && !language.equals("AI")) {
                if(AI.isAiSupported()) {
                    String summary = SummariseCode.getSummary(language, code);
                    tag.put("summary", summary);
                }
            }
        } catch (Exception e) {
            callbacks.printError(e.toString());
        }
        if (numberOfArgs == 1) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
        }
        if (numberOfArgs == 2) {
            tag.put("argument1", argument1);
            tag.put("argument1Type", argument1Type);
            tag.put("argument1Default", argument1DefaultValue);
            tag.put("argument2", argument2);
            tag.put("argument2Type", argument2Type);
            tag.put("argument2Default", argument2DefaultValue);
        }
        tag.put("numberOfArgs", numberOfArgs);
        tag.put("code", code);
        HackvertorExtension.hackvertor.getCustomTags().put(tag);
        saveCustomTags();
        return true;
    }

    public static String generateRandomCodeExecutionKey() {
        byte[] randomBytes = new byte[256];
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            HackvertorExtension.stderr.println("Error get algo:" + e.toString());
            return null;
        }
        secureRandom.nextBytes(randomBytes);
        return DigestUtils.sha256Hex(HackvertorExtension.helpers.bytesToString(randomBytes)).substring(0, 32);
    }

    public static String checkTagExecutionPermissions(String executionKey) {
        boolean codeExecutionTagsEnabled;
        try {
            codeExecutionTagsEnabled = generalSettings.getBoolean("codeExecutionTagsEnabled");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            callbacks.printError("Error loading settings: "  + e);
            throw new RuntimeException(e);
        }
        if (!codeExecutionTagsEnabled) {
            return "Code execution tags are disabled by default. Use settings in the menu bar to enable them. Hackvertor->Settings->Tag permissions->Allow code execution tags";
        }
        if (executionKey == null) {
            return "No execution key defined";
        }
        if (executionKey.length() != 32) {
            return "Code execution key length incorrect";
        }
        if (!tagCodeExecutionKey.equals(executionKey)) {
            return "Incorrect tag code execution key";
        }
        return null;
    }
}
