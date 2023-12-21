package burp;

import burp.ui.ExtensionPanel;
import burp.ui.HackvertorInput;
import burp.ui.HackvertorMessageTab;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;
import java.util.List;

import static burp.Convertors.*;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IExtensionStateListener, IMessageEditorTabFactory {
    //TODO Unset on unload
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String tagCodeExecutionKey = null;
    public static boolean codeExecutionTagsEnabled = false;
    public static Ngrams ngrams;
    public static PrintWriter stderr;
    public static PrintWriter stdout;
    public static Path j2v8TempDirectory;
    public static HashMap<String,String>globalVariables = new HashMap<>();
    /**
     * Native theme will not have the same color scheme as the default Nimbus L&F.
     * The native theme on Windows does not allow the override of button background color.
     */
    public static boolean isNativeTheme;
    public static boolean isDarkTheme;
    public static String argumentsRegex = "(?:0x[a-fA-F0-9]+|\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";
    private List<String> NATIVE_LOOK_AND_FEELS = Arrays.asList("GTK","Windows","Aqua","FlatLaf - Burp Light");
    public static List<String> DARK_THEMES = Arrays.asList("Darcula","FlatLaf - Burp Dark");

    private Hackvertor hackvertor;
    private ExtensionPanel extensionPanel;

    private boolean tagsInProxy = false;
    private boolean tagsInIntruder = true;
    private boolean tagsInRepeater = true;
    private boolean tagsInScanner = true;
    private boolean tagsInExtensions = true;
    private boolean autoUpdateContentLength = true;
    public static boolean allowTagCount = false;
    public static boolean allowAutoConvertClipboard = false;
    public static HashMap<String, Integer> tagCount = new HashMap<>();
   public static final HashMap<String, HashMap<String, Integer>> contextTagCount = new HashMap() {
        {
            put("GET", new HashMap<>());
            put("POST", new HashMap<>());
            put("JSON", new HashMap<>());
        }
    };
    private boolean hvShutdown = false;
    private JMenuBar burpMenuBar;
    private JMenu hvMenuBar;

    public static int MAX_POPULAR_TAGS = 10;

    public static GridBagConstraints createConstraints(int x, int y, int gridWidth, int fill, double weightx, double weighty, int ipadx, int ipady) {
        GridBagConstraints c = new GridBagConstraints();
        c.fill = fill;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = ipadx;
        c.ipady = ipady;
        c.gridwidth = gridWidth;
        c.weightx = weightx;
        c.weighty = weighty;
        return c;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new HackvertorMessageTab(hackvertor);
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = BurpExtender.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            stderr.println("Couldn't find file: " + path);
            return null;
        }
    }

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
            tag.argument1 = new TagArgument("string", tagCodeExecutionKey);
        }
        if (numberOfArgs == 1) {
            String argument1Type = customTag.getString("argument1Type");
            String argument1Default = customTag.getString("argument1Default");
            if (argument1Type.equals("String")) {
                tag.argument1 = new TagArgument("string", argument1Default);
            } else {
                tag.argument1 = new TagArgument("int", argument1Default);
            }
            tag.argument2 = new TagArgument("string", tagCodeExecutionKey);
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
            tag.argument3 = new TagArgument("string", tagCodeExecutionKey);
        }
        return tag;
    }

    public static void print(String s){
        System.out.print(s);
        callbacks.printOutput(s);
    }

    private String generateRandomCodeExecutionKey() {
        byte[] randomBytes = new byte[256];
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            stderr.println("Error get algo:" + e.toString());
            return null;
        }
        secureRandom.nextBytes(randomBytes);
        return DigestUtils.sha256Hex(helpers.bytesToString(randomBytes)).substring(0, 32);
    }

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {
        callbacks = burpCallbacks;
        allowTagCount = Boolean.valueOf(callbacks.loadExtensionSetting("allowTagCount"));
        allowAutoConvertClipboard = Boolean.valueOf(callbacks.loadExtensionSetting("allowAutoConvertClipboard"));
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        hvShutdown = false;
        tagCodeExecutionKey = generateRandomCodeExecutionKey();
        try {
            ngrams = new Ngrams("/quadgrams.txt");
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
        callbacks.setExtensionName("Hackvertor");
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
        Security.addProvider(new BouncyCastleProvider());
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    j2v8TempDirectory = Files.createTempDirectory("j2v8");
                } catch (IOException e) {
                    e.printStackTrace();
                }
                try {
                    hackvertor = new Hackvertor();
	            	stdout.println("Hackvertor v1.8.8");
                    loadCustomTags();
                    loadGlobalVariables();
                    registerPayloadProcessors();
                    extensionPanel = new ExtensionPanel(hackvertor);

                    callbacks.addSuiteTab(BurpExtender.this);
                    burpMenuBar = getBurpFrame().getJMenuBar();
                    hvMenuBar = new JMenu("Hackvertor");
                    final JCheckBoxMenuItem codeExecutionMenu = new JCheckBoxMenuItem(
                            "Allow code execution tags", tagsInProxy);
                    codeExecutionMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (codeExecutionMenu.getState()) {
                                codeExecutionTagsEnabled = true;
                            } else {
                                codeExecutionTagsEnabled = false;
                            }
                        }
                    });
                    hvMenuBar.add(codeExecutionMenu);
                    final JCheckBoxMenuItem tagsInProxyMenu = new JCheckBoxMenuItem(
                            "Allow tags in Proxy", tagsInProxy);
                    tagsInProxyMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInProxyMenu.getState()) {
                                tagsInProxy = true;
                            } else {
                                tagsInProxy = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInProxyMenu);
                    final JCheckBoxMenuItem tagsInIntruderMenu = new JCheckBoxMenuItem(
                            "Allow tags in Intruder", tagsInIntruder);
                    tagsInIntruderMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInIntruderMenu.getState()) {
                                tagsInIntruder = true;
                            } else {
                                tagsInIntruder = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInIntruderMenu);
                    final JCheckBoxMenuItem tagsInRepeaterMenu = new JCheckBoxMenuItem(
                            "Allow tags in Repeater", tagsInRepeater);
                    tagsInRepeaterMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInRepeaterMenu.getState()) {
                                tagsInRepeater = true;
                            } else {
                                tagsInRepeater = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInRepeaterMenu);
                    final JCheckBoxMenuItem tagsInScannerMenu = new JCheckBoxMenuItem(
                            "Allow tags in Scanner", tagsInScanner);
                    tagsInScannerMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInScannerMenu.getState()) {
                                tagsInScanner = true;
                            } else {
                                tagsInScanner = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInScannerMenu);
                    final JCheckBoxMenuItem tagsInExtensionsMenu = new JCheckBoxMenuItem(
                            "Allow tags in Extensions", tagsInExtensions);
                    tagsInExtensionsMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (tagsInExtensionsMenu.getState()) {
                                tagsInExtensions = true;
                            } else {
                                tagsInExtensions = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInExtensionsMenu);
                    final JCheckBoxMenuItem fixContentLengthMenu = new JCheckBoxMenuItem(
                            "Auto update content length", autoUpdateContentLength);
                    fixContentLengthMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (fixContentLengthMenu.getState()) {
                                autoUpdateContentLength = true;
                            } else {
                                autoUpdateContentLength = false;
                            }
                        }
                    });
                    hvMenuBar.add(fixContentLengthMenu);
                    final JCheckBoxMenuItem countTagUsageMenu = new JCheckBoxMenuItem(
                            "Allow Hackvertor to count tag usage", allowTagCount);
                    countTagUsageMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (countTagUsageMenu.getState()) {
                                allowTagCount = true;
                            } else {
                                allowTagCount = false;
                            }
                            callbacks.saveExtensionSetting("allowTagCount", String.valueOf(allowTagCount));
                        }
                    });
                    hvMenuBar.add(countTagUsageMenu);
                    final JCheckBoxMenuItem autoConvertClipboardMenu = new JCheckBoxMenuItem(
                            "Allow Hackvertor to auto convert clipboard", allowAutoConvertClipboard);
                    autoConvertClipboardMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if (autoConvertClipboardMenu.getState()) {
                                allowAutoConvertClipboard = true;
                            } else {
                                allowAutoConvertClipboard = false;
                            }
                            callbacks.saveExtensionSetting("allowAutoConvertClipboard", String.valueOf(allowAutoConvertClipboard));
                        }
                    });
                    hvMenuBar.add(autoConvertClipboardMenu);
                    JMenuItem globalVariablesMenu = new JMenuItem("Global variables");
                    globalVariablesMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showGlobalVariablesWindow();
                        }
                    });
                    JMenuItem createCustomTagsMenu = new JMenuItem("Create custom tag");
                    createCustomTagsMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showCreateEditTagDialog(false, null);
                        }
                    });
                    JMenuItem listCustomTagsMenu = new JMenuItem("List custom tags");
                    listCustomTagsMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showListTagsDialog();
                        }
                    });
                    JMenuItem tagStoreMenu = new JMenuItem("View tag store");
                    tagStoreMenu.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            showTagStore();
                        }
                    });
                    hvMenuBar.add(globalVariablesMenu);
                    hvMenuBar.add(createCustomTagsMenu);
                    hvMenuBar.add(listCustomTagsMenu);
                    hvMenuBar.add(tagStoreMenu);
                    JMenuItem reportBugMenu = new JMenuItem("Report bug/request feature");
                    reportBugMenu.addActionListener(e -> {
                        Utils.openUrl("https://github.com/hackvertor/hackvertor/issues/new");
                    });
                    hvMenuBar.add(reportBugMenu);
                    burpMenuBar.add(hvMenuBar);
                    callbacks.registerMessageEditorTabFactory(BurpExtender.this);
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        });
        //callbacks.printOutput("Look And Feel: "+UIManager.getLookAndFeel().getID());
        isNativeTheme = NATIVE_LOOK_AND_FEELS.contains(UIManager.getLookAndFeel().getID());
        isDarkTheme = DARK_THEMES.contains(UIManager.getLookAndFeel().getID());
    }

    void registerPayloadProcessors() {
        ArrayList<Tag> tags = hackvertor.getTags();
        for(int i=0;i<tags.size();i++) {
            Tag tag = tags.get(i);
            if(tag.argument1 == null) {
                if(tag.name.startsWith("_")) {
                    continue;
                }
                callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor(hackvertor, "Hackvertor_" + capitalise(tag.name), tag.name));
            }
        }
    }

    public void showGlobalVariablesWindow() {
        JPanel createVariablePanel = new JPanel();
        JFrame createVariableWindow = new JFrame("Global variables");
        createVariableWindow.setResizable(false);
        createVariableWindow.setPreferredSize(new Dimension(500, 200));

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
                createVariableWindow.dispose();
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
                globalVariables.put(variableName, variableValue);
                variableCombo.removeAllItems();
                for (String variable : globalVariables.keySet()) {
                    variableCombo.addItem(variable);
                }
                saveGlobalVariables();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
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
        for (String variable : globalVariables.keySet()) {
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
                variableValueField.setText(globalVariables.get(key));
            }
        });
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (variableCombo.getSelectedIndex() == -1) {
                    return;
                }
                globalVariables.remove(variableCombo.getSelectedItem().toString());
                variableCombo.removeAllItems();
                for (String variable : globalVariables.keySet()) {
                    variableCombo.addItem(variable);
                }
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
    public void showCreateEditTagDialog(boolean edit, String editTagName) {
        JPanel createTagPanel = new JPanel(new GridBagLayout());
        createTagPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        JFrame createTagWindow;
        JSONObject customTag = null;
        if (edit) {
            createTagWindow = new JFrame("Edit custom tag");
        } else {
            createTagWindow = new JFrame("Create custom tag");
        }

        if (edit) {
            for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
                customTag = (JSONObject) hackvertor.getCustomTags().get(i);
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
        createTagPanel.add(tagLabel, createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        createTagPanel.add(tagNameField, createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        JLabel languageLabel = new JLabel("Select language");
        JTextComponent.removeKeymap("RTextAreaKeymap");
        HackvertorInput codeArea = new HackvertorInput();
        Utils.fixRSyntaxAreaBurp();
        Utils.configureRSyntaxArea(codeArea);
        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        RTextScrollPane codeScroll = new RTextScrollPane(codeArea);
        codeScroll.setLineNumbersEnabled(true);
        final int[] changes = {0};
        codeArea.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void removeUpdate(DocumentEvent e) {
                changes[0]++;
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                changes[0]++;
            }

            @Override
            public void changedUpdate(DocumentEvent arg0) {
                changes[0]++;
            }
        });
        JComboBox<String> languageCombo = new JComboBox<String>();
        languageCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = languageCombo.getSelectedIndex();
                if (changes[0] > 0) {
                    return;
                }
                String comment = "//";
                if(index == 1) {
                    comment = "#";
                }
                String code = "output = input\n";
                code += comment + "output = convert(\"<@base64>\"+input+\"<@/base64>\")\n";
                code += comment + "output = convert(\"<@customTag('\"+executionKey+\"')>\"+input+\"<@/customTag>\")";
                codeArea.setText(code);
                changes[0] = 0;

                switch(index) {
                    case 0:
                        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                    break;
                    case 1:
                        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_PYTHON);
                    break;
                    case 2:
                        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVA);
                    break;
                    case 3:
                        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_GROOVY);
                    break;
                }
            }
        });
        languageCombo.addItem("JavaScript");
        languageCombo.addItem("Python");
        languageCombo.addItem("Java");
        languageCombo.addItem("Groovy");

        if (edit && customTag != null && customTag.has("language")) {
            if (customTag.getString("language").equals("JavaScript")) {
                languageCombo.setSelectedIndex(0);
            } else if (customTag.getString("language").equals("Python")) {
                languageCombo.setSelectedIndex(1);
            } else if (customTag.getString("language").equals("Java")) {
                languageCombo.setSelectedIndex(2);
            } else if (customTag.getString("language").equals("Groovy")) {
                languageCombo.setSelectedIndex(3);
            }
        }
        if (edit && customTag != null && customTag.has("code")) {
            codeArea.setText(customTag.getString("code"));
        }
        Container pane = createTagWindow.getContentPane();
        createTagPanel.add(languageLabel, createConstraints(0, 1, 1, GridBagConstraints.BOTH, 0, 0, 5, 5));
        createTagPanel.add(languageCombo, createConstraints(1, 1, 1, GridBagConstraints.BOTH, 0, 0, 5, 5));
        JLabel argument1Label = new JLabel("Argument1");
        JComboBox<String> argument1Combo = new JComboBox<String>();
        argument1Combo.addItem("None");
        argument1Combo.addItem("String");
        argument1Combo.addItem("Number");
        if (edit && customTag != null && customTag.has("argument1Type")) {
            if (customTag.getString("argument1Type").equals("String")) {
                argument1Combo.setSelectedIndex(1);
            } else if (customTag.getString("argument1Type").equals("Number")) {
                argument1Combo.setSelectedIndex(2);
            }
        }
        JLabel argument1NameLabel = new JLabel("Param Name");
        JTextField argument1NameField = new JTextField();
        if (edit && customTag != null && customTag.has("argument1")) {
            argument1NameField.setText(customTag.getString("argument1"));
        }
        JLabel argument1DefaultLabel = new JLabel("Default value");
        JTextField argument1DefaultValueField = new JTextField();
        if (edit && customTag != null && customTag.has("argument1Default")) {
            argument1DefaultValueField.setText(customTag.getString("argument1Default"));
        }
        JPanel argument1Panel = new JPanel();
        argument1Panel.setBorder(new EmptyBorder(0, 0, 0, 10));
        argument1Panel.setPreferredSize(new Dimension(400, 300));
        argument1Panel.setLayout(new GridBagLayout());
        argument1Panel.add(argument1Label, createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument1Panel.add(argument1Combo, createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument1Panel.add(argument1NameLabel, createConstraints(0, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument1Panel.add(argument1NameField, createConstraints(1, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument1Panel.add(argument1DefaultLabel, createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument1Panel.add(argument1DefaultValueField, createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        createTagPanel.add(argument1Panel, createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));

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
        argument2Panel.add(argument2Label, createConstraints(0, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument2Panel.add(argument2Combo, createConstraints(1, 0, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument2Panel.add(argument2NameLabel, createConstraints(0, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument2Panel.add(argument2NameField, createConstraints(1, 1, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument2Panel.add(argument2DefaultLabel, createConstraints(0, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        argument2Panel.add(argument2DefaultValueField, createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        createTagPanel.add(argument2Panel, createConstraints(1, 2, 1, GridBagConstraints.BOTH, 1, 0, 5, 5));
        JLabel convertLabel = new JLabel("You can now convert Hackvertor tags inside customTags!");
        JLabel codeLabel = new JLabel("Code (if you end the code with .js/.py/.java/.groovy it will read a file)");
        createTagPanel.add(convertLabel, createConstraints(0, 3, 2, GridBagConstraints.BOTH, 0, 0, 5, 5));
        createTagPanel.add(codeLabel, createConstraints(0, 4, 2, GridBagConstraints.BOTH, 0, 0, 5, 5));
        createTagPanel.add(codeScroll, createConstraints(0, 5, 2, GridBagConstraints.BOTH, 1, 1, 5, 5));
        JButton cancelButton = new JButton("Cancel");
        if (!isNativeTheme && !isDarkTheme) {
            cancelButton.setBackground(Color.decode("#005a70"));
            cancelButton.setForeground(Color.white);
        }
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createTagWindow.dispose();
            }
        });
        JLabel errorMessage = new JLabel();
        errorMessage.setForeground(Color.red);
        JButton createButton = new JButton("Create tag");
        JButton exportButton = new JButton("Export to tag store");
        JSONObject finalCustomTag = customTag;
        exportButton.addActionListener(e -> {
            loadCustomTags();
            for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
                JSONObject savedCustomTag = (JSONObject) hackvertor.getCustomTags().get(i);
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
                    alert("Copied JSON data to clipboard.");
                    Utils.openUrl("https://github.com/hackvertor/hackvertor/tag-store/README.md");
                    return;
                }
            }
            alert("Unable to find tag");
        });
        if (edit) {
            createButton.setText("Update tag");
        }
        JButton testButton = new JButton("Test tag");
        testButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String tagName = Utils.sanitizeTagName(tagNameField.getText());
                String language = languageCombo.getSelectedItem().toString();
                String code = codeArea.getText();
                String argument1 = argument1NameField.getText();
                String argument1DefaultValue = argument1DefaultValueField.getText();
                String argument2 = argument2NameField.getText();
                String argument2DefaultValue = argument2DefaultValueField.getText();
                String argument1Type = argument1Combo.getSelectedItem().toString();
                String argument2Type = argument2Combo.getSelectedItem().toString();
                int numberOfArgs = 0;
                if (argument1Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                if (argument2Combo.getSelectedIndex() > 0) {
                    numberOfArgs++;
                }
                String input = JOptionPane.showInputDialog(null, "Enter input for your tag", "test");
                String output = "";

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
                    if (language.equals("JavaScript")) {
                        output = javascript(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions, hackvertor.getCustomTags(), null);
                    } else if(language.equals("Python")){
                        output = python(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions, hackvertor.getCustomTags(), null);
                    } else if(language.equals("Java")){
                        output = java(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions, hackvertor.getCustomTags(), null);
                    } else if(language.equals("Groovy")){
                        output = groovy(new HashMap<>(), input, code, tagCodeExecutionKey, customTagOptions, hackvertor.getCustomTags(), null);
                    }
                }catch (Exception ee){
                    ee.printStackTrace();
                }
                alert("Output from tag:" + output);
            }
        });
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String tagName = Utils.sanitizeTagName(tagNameField.getText());
                String language = languageCombo.getSelectedItem().toString();
                String code = codeArea.getText();
                String argument1 = argument1NameField.getText();
                String argument1DefaultValue = argument1DefaultValueField.getText();
                String argument2 = argument2NameField.getText();
                String argument2DefaultValue = argument2DefaultValueField.getText();

                int numberOfArgs = 0;
                if (!Utils.validateTagName(tagName)) {
                    errorMessage.setText("Invalid tag name. Use a-zA-Z_0-9 for tag names");
                    return;
                }
                if (!Utils.validateCode(code)) {
                    errorMessage.setText("Please enter some code. Code cannot be blank or exceed " + Utils.MAX_TAG_CODE_LEN + " bytes");
                    return;
                }
                if (argument1Combo.getSelectedIndex() > 0 && !Utils.validateParam(argument1)) {
                    errorMessage.setText("Invalid param name. For argument1. Use " + Utils.paramRegex);
                    return;
                }
                if (argument1Combo.getSelectedItem().equals("Number") && !Utils.validateTagParamNumber(argument1DefaultValue)) {
                    errorMessage.setText("Invalid default value for argument1. Use " + Utils.numberRegex);
                    return;
                }
                if (argument2Combo.getSelectedIndex() > 0 && !Utils.validateParam(argument2)) {
                    errorMessage.setText("Invalid param name for argument2. Use " + Utils.paramRegex);
                    return;
                }
                if (argument2Combo.getSelectedIndex() > 0 && argument1Combo.getSelectedIndex() == 0) {
                    errorMessage.setText("You have selected two arguments but not defined the first.");
                    return;
                }
                if (argument2Combo.getSelectedItem().toString().equals("Number") && !Utils.validateTagParamNumber(argument2DefaultValue)) {
                    errorMessage.setText("Invalid default value for argument2. Use " + Utils.numberRegex);
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
                    createCustomTag(tagName, language, code, argument1, argument1Combo.getSelectedItem().toString(), argument1DefaultValue, argument2, argument2Combo.getSelectedItem().toString(), argument2DefaultValue, numberOfArgs);
                }
                extensionPanel.refresh();
                createTagWindow.dispose();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            createButton.setBackground(Color.decode("#005a70"));
            createButton.setForeground(Color.white);
            testButton.setBackground(Color.decode("#005a70"));
            testButton.setForeground(Color.white);
            exportButton.setBackground(Color.decode("#005a70"));
            exportButton.setForeground(Color.white);
        }
        JPanel buttonsPanel = new JPanel(new GridBagLayout());
        buttonsPanel.add(cancelButton, createConstraints(0, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5));
        if(edit) {
            buttonsPanel.add(exportButton, createConstraints(1, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5));
        }
        buttonsPanel.add(testButton, createConstraints(2, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5));
        buttonsPanel.add(createButton, createConstraints(3, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5));
        buttonsPanel.add(errorMessage, createConstraints(4, 0, 1, GridBagConstraints.NONE, 0, 0, 5, 5));
        createTagPanel.add(buttonsPanel,createConstraints(0, 6, 2, GridBagConstraints.NONE, 1, 0, 5, 5)) ;
        pane.add(createTagPanel);
        createTagWindow.pack();
        createTagWindow.setLocationRelativeTo(null);
        createTagWindow.setVisible(true);
    }

    public void showTagStore() {
        final String TAG_STORE_URL = "https://raw.githubusercontent.com/hackvertor/hackvertor/master/tag-store/";
        //final String TAG_STORE_URL = "http://127.0.0.1:4000/";
        String jsonResponse = makeHttpRequest(TAG_STORE_URL + "tag-store.json", "GET");
        if(jsonResponse == null) {
            callbacks.printError("Unable to load tag store JSON");
            alert("Unable to load the tag store. Store may be down.");
            return;
        }
        JSONArray tagStore;
        try {
            tagStore = new JSONArray(jsonResponse);
        } catch (JSONException ex) {
            alert("Unable to load the tag store. Store may be down.");
            callbacks.printError("Invalid JSON");
            return;
        }

        if(tagStore.isEmpty()) {
            alert("Unable to load the tag store. Tag store JSON not found.");
            callbacks.printError("Unable to retrieve JSON");
            return;
        }
        HashMap<String, String> storeCode = new HashMap<>();
        JFrame tagStoreWindow = new JFrame("Hackvertor tag store");
        JPanel optionsPanel = new JPanel(new BorderLayout());
        Utils.setMarginAndPadding(optionsPanel, 10);
        optionsPanel.setVisible(false);
        JLabel title = new JLabel("Title here");
        Utils.setMarginAndPadding(title, 10);
        title.setFont(new Font("Arial",Font.BOLD,30));
        title.putClientProperty("html.disable", Boolean.TRUE);
        JPanel buttonsPanel = new JPanel(new BorderLayout());
        Utils.setMarginAndPadding(buttonsPanel, 10);
        JButton installButton = new JButton("Install tag");
        JButton closeButton = new JButton("Close");
        buttonsPanel.add(closeButton, BorderLayout.WEST);
        buttonsPanel.add(installButton, BorderLayout.EAST);
        closeButton.addActionListener(e -> {
            tagStoreWindow.dispose();
        });
        Utils.setMarginAndPadding(closeButton, 10);
        Utils.setMarginAndPadding(installButton, 10);
        optionsPanel.add(title, BorderLayout.NORTH);
        JTextComponent.removeKeymap("RTextAreaKeymap");
        HackvertorInput codeArea = new HackvertorInput();
        codeArea.setEditable(false);
        codeArea.setText("Code goes here");
        Utils.fixRSyntaxAreaBurp();
        Utils.configureRSyntaxArea(codeArea);
        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        JScrollPane codeScroller = new JScrollPane(codeArea);
        Utils.setMarginAndPadding(codeScroller, 10);
        JTextArea description = new JTextArea("Description goes here");
        description.setEditable(false);
        description.putClientProperty("html.disable", Boolean.TRUE);
        JScrollPane descScroller = new JScrollPane(description, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        Utils.setMarginAndPadding(descScroller, 10);
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(descScroller, BorderLayout.NORTH);
        centerPanel.add(codeScroller, BorderLayout.CENTER);
        optionsPanel.add(centerPanel, BorderLayout.CENTER);
        optionsPanel.add(buttonsPanel, BorderLayout.SOUTH);
        JPanel tagStorePanel = new JPanel(new BorderLayout());
        String[] columnNames = {"Tag name", "Author", "Language"};
        DefaultTableModel tagStoreModel = new DefaultTableModel(columnNames, 0);
        HashMap<String, JSONObject> storeTags = new HashMap();
        for(int i=0;i<tagStore.length();i++) {
            JSONObject tag = (JSONObject) tagStore.get(i);
            String tagName = tag.getString("tagName");
            String author = tag.getString("author");
            String language = tag.getString("language");
            tagStoreModel.addRow(new Object[]{tagName,author,language});
            storeTags.put(tagName, tag);
        }
        JTable storeTable = new JTable(tagStoreModel);
        storeTable.setDefaultEditor(Object.class, null);
        storeTable.putClientProperty("html.disable", Boolean.TRUE);
        storeTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ListSelectionModel selectionModel = storeTable.getSelectionModel();
        installButton.addActionListener(e -> {
            alert("Custom tags can compromise your system. Please ensure you've evaluated the code before you install it.");
            int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you want to install this custom tag?");
            if(confirm == 0) {
                int selectedRow = storeTable.getSelectedRow();
                String tagName = (String) storeTable.getValueAt(selectedRow, 0);
                if (!Utils.validateTagName(tagName)) {
                    alert("Invalid tag name. Use a-zA-Z_0-9 for tag names");
                    return;
                }
                String code = storeCode.get(tagName);
                JSONObject tag = storeTags.get(tagName);
                int numberOfArgs = tag.getInt("numberOfArgs");
                String language = tag.getString("language");
                if (!Utils.validateCode(code)) {
                    alert("Invalid code unable to install tag. Code cannot be blank or exceed " + Utils.MAX_TAG_CODE_LEN + " bytes");
                    return;
                }
                String argument1 = null;
                String argument1Type = null;
                String argument1Default = null;
                String argument2 = null;
                String argument2Type = null;
                String argument2Default = null;
                if(numberOfArgs > 0) {
                    argument1 = tag.getString("argument1");
                    argument1Type = tag.getString("argument1Type");
                    argument1Default = tag.getString("argument1Default");
                    argument2 = tag.getString("argument2");
                    argument2Type = tag.getString("argument2Type");
                    argument2Default = tag.getString("argument2Default");
                    if (!Utils.validateParam(argument1)) {
                        alert("Invalid param name. For argument1. Use " + Utils.paramRegex);
                        return;
                    }
                    if (argument1Type.equals("Number") && !Utils.validateTagParamNumber(argument1Default)) {
                        alert("Invalid default value for argument1. Use " + Utils.numberRegex);
                        return;
                    }
                    if (!Utils.validateParam(argument2)) {
                        alert("Invalid param name for argument2. Use " + Utils.paramRegex);
                        return;
                    }
                    if (argument2Type.equals("Number") && !Utils.validateTagParamNumber(argument2Default)) {
                        alert("Invalid default value for argument2. Use " + Utils.numberRegex);
                        return;
                    }
                }
                loadCustomTags();
                if(hackvertor.hasCustomTag(tagName)) {
                    updateCustomTag("_" + tagName, language, code, argument1, argument1Type, argument1Default, argument2, argument2Type, argument2Default, numberOfArgs);
                } else {
                    createCustomTag(tagName, language, code, argument1, argument1Type, argument1Default, argument2, argument2Type, argument2Default, numberOfArgs);
                }
                loadCustomTags();
                alert("Successfully installed the tag");
            }
        });
        selectionModel.addListSelectionListener(e -> {
            if(e.getValueIsAdjusting()) {
                return;
            }
            int selectedRow = storeTable.getSelectedRow();
            String tagName = (String) storeTable.getValueAt(selectedRow, 0);
            tagName = Utils.sanitizeTagName(tagName);
            String code = null;
            loadCustomTags();
            if(hackvertor.hasCustomTag(tagName)) {
                installButton.setEnabled(false);
            } else {
                installButton.setEnabled(true);
            }

            if(storeCode.containsKey(tagName)) {
                code = storeCode.get(tagName);
            } else {
                code = makeHttpRequest(TAG_STORE_URL+tagName+"/"+tagName+Utils.getExtensionFromLanguage(storeTags.get(tagName).getString("language")), "GET");
                if(code == null) {
                    callbacks.printError("Unable get retrieve code for tag:"+tagName);
                    return;
                }
                storeCode.put(tagName, code);
            }
            title.setText(tagName);
            description.setText(storeTags.get(tagName).getString("description"));
            String language = storeTags.get(tagName).getString("language");

            switch(language) {
                case "JavaScript":
                    codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                    break;
                case "Python":
                    codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_PYTHON);
                    break;
                case "Java":
                    codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVA);
                    break;
                case "Groovy":
                    codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_GROOVY);
                    break;
            }
            codeArea.setTabSize(3);
            codeArea.setText(code);
            codeArea.setCaretPosition(0);
            optionsPanel.setVisible(true);
        });
        JScrollPane scrollPane = new JScrollPane(storeTable);
        tagStorePanel.add(scrollPane, BorderLayout.WEST);
        tagStorePanel.add(optionsPanel, BorderLayout.CENTER);
        tagStoreWindow.add(tagStorePanel);
        tagStoreWindow.setResizable(true);
        tagStoreWindow.setPreferredSize(new Dimension(1000, 700));
        tagStoreWindow.pack();
        tagStoreWindow.setLocationRelativeTo(null);
        tagStoreWindow.setVisible(true);
    }

    public String makeHttpRequest(String requestUrl, String method) {
        HttpURLConnection connection = null;

        try {
            URL url = new URI(requestUrl).toURL();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setUseCaches(false);
            connection.setDoOutput(true);
            connection.setRequestMethod(method);
            InputStream is = connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append(System.lineSeparator());
            }
            rd.close();
            return response.toString();
        } catch (Exception e) {
            callbacks.printError("Error making HTTP request:" + e);
            e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public void showListTagsDialog() {
        JPanel listTagsPanel = new JPanel();
        JFrame listTagsWindow = new JFrame("List custom tags");
        listTagsWindow.setResizable(false);
        listTagsWindow.setPreferredSize(new Dimension(500, 150));
        JLabel tagLabel = new JLabel("Tag");
        tagLabel.setPreferredSize(new Dimension(50, 25));
        JComboBox tagCombo = new JComboBox();
        tagCombo.setPreferredSize(new Dimension(200, 25));
        listTagsPanel.add(tagLabel);
        listTagsPanel.add(tagCombo);
        for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
            tagCombo.addItem(customTag.getString("tagName"));
        }
        JButton editButton = new JButton("Edit tag");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (tagCombo.getSelectedIndex() == -1) {
                    return;
                }
                showCreateEditTagDialog(true, tagCombo.getSelectedItem().toString());
            }
        });
        JButton deleteButton = new JButton("Delete tag");
        JButton loadButton = new JButton("Load tags from clipboard");
        JButton exportButton = new JButton("Export all my tags to clipboard");
        exportButton.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection customTagsJSON = new StringSelection(hackvertor.getCustomTags().toString());
            clipboard.setContents(customTagsJSON, null);
        });
        loadButton.addActionListener(e -> {
            int input = JOptionPane.showConfirmDialog(null, "Are you sure you sure you want to load all tags from the clipboard? This will replace your existing tags");
            if (input != 0) {
                return;
            }
            try {
                String tagsJSON = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
                if (tagsJSON != null && tagsJSON.length() > 0) {
                    try {
                        JSONArray tags = new JSONArray(tagsJSON);
                        hackvertor.setCustomTags(tags);
                        alert("All your tags have been replaced from the clipboard");
                        saveCustomTags();
                        listTagsWindow.dispose();
                        showListTagsDialog();
                    } catch (JSONException ex) {
                        alert("Invalid JSON");
                    }
                }
            } catch (UnsupportedFlavorException unsupportedFlavorException) {
                unsupportedFlavorException.printStackTrace();
                alert("Invalid JSON");
            } catch (IOException ioException) {
                ioException.printStackTrace();
                alert("Invalid JSON");
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
            for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
                JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
                if (tagCombo.getSelectedItem().toString().equals(customTag.getString("tagName"))) {
                    hackvertor.getCustomTags().remove(i);
                    tagCombo.removeItemAt(tagCombo.getSelectedIndex());
                    saveCustomTags();
                    break;
                }
            }
            extensionPanel.refresh();
        });
        if (!isNativeTheme && !isDarkTheme) {
            deleteButton.setBackground(Color.decode("#005a70"));
            deleteButton.setForeground(Color.white);
            editButton.setBackground(Color.decode("#005a70"));
            editButton.setForeground(Color.white);
            exportButton.setBackground(Color.decode("#005a70"));
            exportButton.setForeground(Color.white);
            loadButton.setBackground(Color.decode("#005a70"));
            loadButton.setForeground(Color.white);
        }
        listTagsPanel.add(editButton);
        listTagsPanel.add(deleteButton);
        listTagsPanel.add(loadButton);
        listTagsPanel.add(exportButton);
        listTagsWindow.add(listTagsPanel);
        listTagsWindow.pack();
        listTagsWindow.setLocationRelativeTo(null);
        listTagsWindow.setVisible(true);
    }

    public void loadCustomTags() {
        String json = callbacks.loadExtensionSetting("customTags");
        if (json != null && json.length() > 0) {
            try {
                hackvertor.setCustomTags(new JSONArray(json));
            } catch (JSONException e) {
                alert("Failed to load custom tags");
            }
        }
    }

    public void saveCustomTags() {
        callbacks.saveExtensionSetting("customTags", hackvertor.getCustomTags().toString());
    }
    public void saveGlobalVariables() {
        JSONObject json = new JSONObject(globalVariables);
        callbacks.saveExtensionSetting("globalVariables", json.toString());
    }
    public void loadGlobalVariables() {
        String json = callbacks.loadExtensionSetting("globalVariables");
        if (json != null && json.length() > 0) {
            try {
                JSONObject jsonObject = new JSONObject(json);
                Iterator<String> keys = jsonObject.keys();
                while(keys.hasNext()) {
                    String key = keys.next();
                    globalVariables.put(key, jsonObject.get(key).toString());
                }
            } catch (JSONException e) {
                alert("Failed to load global variables");
            }
        }
    }

    public void updateCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
        JSONObject tag = new JSONObject();
        tag.put("tagName", tagName);
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
        for (int i = 0; i < hackvertor.getCustomTags().length(); i++) {
            JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
            if (tagName.equals(customTag.getString("tagName"))) {
                hackvertor.getCustomTags().put(i, tag);
                saveCustomTags();
                break;
            }
        }
        saveCustomTags();
    }

    public void createCustomTag(String tagName, String language, String code, String argument1, String argument1Type, String argument1DefaultValue, String argument2, String argument2Type, String argument2DefaultValue, int numberOfArgs) {
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
        hackvertor.getCustomTags().put(tag);
        saveCustomTags();
    }

    public void extensionUnloaded() {
        hvShutdown = true;
        burpMenuBar.remove(hvMenuBar);
        burpMenuBar.revalidate();
        burpMenuBar.repaint();
        callbacks.printOutput("Hackvertor unloaded");
    }

    public byte[] fixContentLength(byte[] request) {
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        if (countMatches(request, helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = analyzedRequest.getBodyOffset();
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        } else {
            return request;
        }
    }

    public int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ':') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 1);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    public byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(helpers.stringToBytes(" " + value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            throw new RuntimeException("Can't find the header");
        }
    }

    int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                if (!tagsInProxy) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                if (!tagsInIntruder) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                if (!tagsInRepeater) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                if (!tagsInScanner) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                if (!tagsInExtensions) {
                    return;
                }
                break;
            default:
                return;
        }
        byte[] request = messageInfo.getRequest();
        if (helpers.indexOf(request, helpers.stringToBytes("<@"), false, 0, request.length) > -1) {
            String requestStr = helpers.bytesToString(request);
            hackvertor.analyzeRequest(helpers.stringToBytes(Hackvertor.removeHackvertorTags(requestStr)), messageInfo);
            request = helpers.stringToBytes(hackvertor.convert(requestStr, hackvertor));
            if (autoUpdateContentLength) {
                request = fixContentLength(request);
            }
            messageInfo.setRequest(request);
        }
    }

    private static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    public String getTabCaption() {
        return "Hackvertor";
    }

    public String buildUrl(URL url) {
        int port = url.getPort();
        StringBuilder urlResult = new StringBuilder();
        urlResult.append(url.getProtocol());
        urlResult.append(":");
        if (url.getAuthority() != null && url.getAuthority().length() > 0) {
            urlResult.append("//");
            urlResult.append(url.getHost());
        }

        if ((url.getProtocol().equals("http") && port != 80) || (url.getProtocol().equals("https") && port != 443) && port != -1) {
            urlResult.append(':').append(port);
        }
        if (url.getPath() != null) {
            urlResult.append(url.getPath());
        }
        if (url.getQuery() != null) {
            urlResult.append("?");
            urlResult.append(url.getQuery());
        }
        if (url.getRef() != null) {
            urlResult.append("#");
            urlResult.append(url.getRef());
        }
        return urlResult.toString();
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        int[] bounds = invocation.getSelectionBounds();
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                break;
            default:
                return null;
        }
        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenu submenu = new JMenu("Hackvertor");
        Action hackvertorAction;
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE && bounds != null && bounds[0] == bounds[1]) {
            hackvertorAction = new HackvertorAction("Send response body to Hackvertor", extensionPanel, invocation);
        } else {
            hackvertorAction = new HackvertorAction("Send to Hackvertor", extensionPanel, invocation);
        }
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction);
        submenu.add(sendToHackvertor);

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
            menu.add(submenu);
            return menu;
        }

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            String converted = hackvertor.convert(helpers.bytesToString(invocation.getSelectedMessages()[0].getRequest()), null);
            URL url = helpers.analyzeRequest(invocation.getSelectedMessages()[0].getHttpService(), helpers.stringToBytes(converted)).getUrl();
            StringSelection stringSelection = null;
            stringSelection = new StringSelection(buildUrl(url));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        });
        submenu.add(copyUrl);

        JMenuItem convert = new JMenuItem("Convert tags");
        convert.addActionListener(e -> {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                invocation.getSelectedMessages()[0].setRequest(helpers.stringToBytes(hackvertor.convert(helpers.bytesToString(message), null)));
            }
        });
        submenu.add(convert);
        JMenuItem autodecodeConvert = new JMenuItem("Auto decode & Convert");
        autodecodeConvert.addActionListener(e -> {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                byte[] selection = Arrays.copyOfRange(message, bounds[0], bounds[1]);
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    byte[] convertedSelection = helpers.stringToBytes(auto_decode_no_decrypt(helpers.bytesToString(selection)));
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                    outputStream.write(convertedSelection);
                    outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                    Object source = invocation.getInputEvent().getSource();
                    if (source instanceof JTextArea) {
                        ((JTextArea) source).select(bounds[0], bounds[0] + convertedSelection.length);
                    }
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
            }
        });
        loadCustomTags();
        submenu.add(autodecodeConvert);
        if(allowTagCount) {
            JMenu contextPopularTags = new JMenu("Popular tags for this context");
            ArrayList<Tag> tags = hackvertor.getTags();
            byte[] message = invocation.getSelectedMessages()[0].getRequest();
            IRequestInfo analyzedRequest = helpers.analyzeRequest(message);
            String context = Utils.getContext(analyzedRequest);
            if(contextTagCount.containsKey(context)) {
                if(contextTagCount.get(context) != null) {
                    contextTagCount.get(context).entrySet().stream().limit(MAX_POPULAR_TAGS)
                            .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                            .forEach(entry -> {
                                JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "(" + entry.getValue() + ")");
                                Tag tagObj = Utils.getTagByTagName(tags, entry.getKey());
                                tagMenuItem.addActionListener(Utils.generateTagActionListener(invocation, tagObj));
                                contextPopularTags.add(tagMenuItem);
                            });
                    submenu.add(contextPopularTags);
                }
            }
            JMenu popularTags = new JMenu("Popular tags");
            tagCount.entrySet().stream().limit(MAX_POPULAR_TAGS)
                    .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                    .forEach(entry -> {
                        JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "("+entry.getValue()+")");
                        Tag tagObj = Utils.getTagByTagName(tags, entry.getKey());
                        tagMenuItem.addActionListener(Utils.generateTagActionListener(invocation, tagObj));
                        popularTags.add(tagMenuItem);
                    });
            submenu.add(popularTags);
        }

        submenu.addSeparator();
        for (int i = 0; i < Tag.Category.values().length; i++) {
            Tag.Category category = Tag.Category.values()[i];
            JMenu categoryMenu = Utils.createTagMenuForCategory(hackvertor.getTags(), category, invocation, "", false, null);
            submenu.add(categoryMenu);
        }
        menu.add(submenu);
        return menu;
    }

    public void alert(String msg) {
        JOptionPane.showMessageDialog(null, msg);
    }

    public Component getUiComponent() {
        return extensionPanel;
    }
}
