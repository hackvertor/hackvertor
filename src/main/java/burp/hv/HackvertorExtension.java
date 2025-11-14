package burp.hv;

import burp.*;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burp.api.montoya.utilities.CompressionType;
import burp.hv.settings.Settings;
import burp.hv.tags.CustomTags;
import burp.hv.tags.Tag;
import burp.hv.tags.TagAutomator;
import burp.hv.tags.TagStore;
import burp.hv.ui.*;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.RoundRectangle2D;
import java.io.*;
import java.security.Security;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.hv.Convertors.*;
import static burp.hv.utils.TagUtils.generateTagActionListener;

public class HackvertorExtension implements BurpExtension, IBurpExtender, ITab, IExtensionStateListener, IMessageEditorTabFactory {
    //TODO Unset on unload
    public static String extensionName = "Hackvertor";
    public static String version = "v2.2.13";
    public static JFrame HackvertorFrame = null;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static String tagCodeExecutionKey = null;
    public static Ngrams ngrams;
    public static PrintWriter stderr;
    public static PrintWriter stdout;
    public static MontoyaApi montoyaApi;
    public static Settings generalSettings;
    public static HashMap<String,String>globalVariables = new HashMap<>();
    public static boolean isNativeTheme;
    public static boolean isDarkTheme;
    private List<String> NATIVE_LOOK_AND_FEELS = Arrays.asList("GTK","Windows","Aqua","FlatLaf - Burp Light");
    public static List<String> DARK_THEMES = Arrays.asList("Darcula","FlatLaf - Burp Dark");

    public static Hackvertor hackvertor;
    public static ExtensionPanel extensionPanel;

    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static int requestHistoryPos = 0;
    public static boolean hasHotKey = false;
    public static ArrayList<HttpRequest> requestHistory = new ArrayList<>();
    public static HashMap<String, Integer> tagCount = new HashMap<>();
    public static final HashMap<String, HashMap<String, Integer>> contextTagCount = new HashMap() {
        {
            put("GET", new HashMap<>());
            put("POST", new HashMap<>());
            put("JSON", new HashMap<>());
        }
    };
    private JMenuBar burpMenuBar;

    public static int MAX_POPULAR_TAGS = 10;
    public static String lastTagUsed = null;

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new HackvertorMessageTab(hackvertor);
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = HackvertorExtension.class.getResource(path);
        if (imgURL != null) {
            ImageIcon img = new ImageIcon(imgURL, description);
            Image resizedImage = img.getImage().getScaledInstance(80, 80, Image.SCALE_SMOOTH);
            return new ImageIcon(resizedImage);
        } else {
            stderr.println("Couldn't find file: " + path);
            return null;
        }
    }

    public static void print(String s){
        System.out.print(s);
        callbacks.printOutput(s);
    }

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks burpCallbacks) {
        generalSettings = new Settings("general", burpCallbacks);
        Utils.registerGeneralSettings(generalSettings);
        generalSettings.load();
        callbacks = burpCallbacks;
        helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStdout(), true);
        tagCodeExecutionKey = CustomTags.generateRandomCodeExecutionKey();
        callbacks.setExtensionName(extensionName);
        Security.addProvider(new BouncyCastleProvider());
        SwingUtilities.invokeLater(() -> {
            try {
                hackvertor = new Hackvertor();
                stdout.println(extensionName + " " + version);
                CustomTags.loadCustomTags();
                Variables.loadGlobalVariables();
                registerPayloadProcessors();
                extensionPanel = new ExtensionPanel(hackvertor);
                callbacks.addSuiteTab(this);
                callbacks.registerMessageEditorTabFactory(HackvertorExtension.this);
                callbacks.registerExtensionStateListener(this);
                // Restore state after the UI is fully initialized
                SwingUtilities.invokeLater(() -> {
                    extensionPanel.restoreState();
                });
            } catch (Exception ignored){

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
                callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor(hackvertor, extensionName+ "_" + capitalise(tag.name), tag.name));
            }
        }
    }

    public void extensionUnloaded() {
        // Save ExtensionPanel state before unloading
        if (extensionPanel != null) {
            extensionPanel.saveState();
        }

        if(HackvertorFrame != null) {
            HackvertorFrame.removeAll();
            HackvertorFrame.dispose();
            HackvertorFrame = null;
        }
        executorService.shutdownNow();
        ngrams = null;
        callbacks.printOutput(extensionName + " unloaded");
    }

    public String getTabCaption() {
        return extensionName;
    }

    public static void alert(String msg) {
        JOptionPane.showMessageDialog(null, msg);
    }

    public Component getUiComponent() {
        return extensionPanel;
    }

    //Used in tests
    public static void setHelpers(IExtensionHelpers helpers) {
        HackvertorExtension.helpers = helpers;
    }

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        HackvertorExtension.montoyaApi = montoyaApi;
        montoyaApi.userInterface().menuBar().registerMenu(Utils.generateHackvertorMenuBar());
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        montoyaApi.http().registerHttpHandler(new HackvertorHttpHandler());
        montoyaApi.userInterface().registerContextMenuItemsProvider(new HackvertorContextMenu());

        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
            registerAllHotkeys(montoyaApi, burp);
        }
    }

    private void registerAllHotkeys(MontoyaApi montoyaApi, Burp burp) {
        List<HotkeyDefinition> hotkeys = Arrays.asList(
            new HotkeyDefinition("Convert", "Ctrl+Alt+C", event -> {
                if (event.messageEditorRequestResponse().isEmpty()) {
                    return;
                }
                MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().get();
                if(!requestResponse.selectionContext().toString().equalsIgnoreCase("request")) {
                    return;
                }
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    event.messageEditorRequestResponse().get().setRequest(HttpRequest.httpRequest(request.httpService(), HackvertorExtension.hackvertor.convert(request.toString(), HackvertorExtension.hackvertor)));
                }
            }),
            new HotkeyDefinition("Find a tag", "Ctrl+Alt+F", event -> {
                SwingUtilities.invokeLater(() -> {
                    ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();

                    JWindow findTagWindow = new JWindow(montoyaApi.userInterface().swingUtils().suiteFrame());
                    findTagWindow.setLayout(new BorderLayout());

                    // Use shaped window for better performance
                    try {
                        findTagWindow.setBackground(new Color(0, 0, 0, 0));
                        SwingUtilities.invokeLater(() -> {
                            Shape shape = new RoundRectangle2D.Float(0, 0, 750, 500, 20, 20);
                            findTagWindow.setShape(shape);
                        });
                    } catch (UnsupportedOperationException e) {
                        // Fallback if shaped windows not supported
                    }

                    JPanel mainPanel = new JPanel(new BorderLayout());
                    mainPanel.setBackground(new Color(255, 255, 255));
                    mainPanel.setOpaque(true);
                    mainPanel.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(229, 231, 235), 1),
                        BorderFactory.createEmptyBorder(14, 14, 14, 14)
                    ));

                    JPanel searchPanel = new JPanel(new BorderLayout());
                    searchPanel.setBackground(new Color(255, 255, 255));
                    searchPanel.setOpaque(true);
                    searchPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));
                    JLabel searchLabel = new JLabel("Search tags: ");
                    searchLabel.setForeground(new Color(107, 114, 128));
                    searchLabel.setFont(new Font("Inter", Font.PLAIN, 13));
                    JTextField searchField = new JTextField();
                    searchField.setFont(new Font("Monospaced", Font.PLAIN, 14));
                    searchField.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(209, 213, 219), 1),
                        BorderFactory.createEmptyBorder(6, 8, 6, 8)
                    ));
                    searchPanel.add(searchLabel, BorderLayout.WEST);
                    searchPanel.add(searchField, BorderLayout.CENTER);

                    JPanel tagsPanel = new JPanel(new GridBagLayout());
                    tagsPanel.setOpaque(true);
                    tagsPanel.setBackground(new Color(255, 255, 255));

                    JScrollPane scrollPane = new JScrollPane(tagsPanel);
                    scrollPane.setPreferredSize(new Dimension(700, 450));
                    scrollPane.setBorder(BorderFactory.createEmptyBorder());
                    scrollPane.getVerticalScrollBar().setUnitIncrement(16);

                    // Track first visible tag for Enter key
                    final Tag[] firstVisibleTag = {null};

                    Runnable updateTags = () -> {
                        tagsPanel.removeAll();
                        firstVisibleTag[0] = null;
                        String searchText = searchField.getText().toLowerCase();
                        GridBagConstraints gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridy = 0;
                        gbc.insets = new Insets(3, 3, 3, 3);
                        gbc.anchor = GridBagConstraints.WEST;
                        gbc.fill = GridBagConstraints.HORIZONTAL;

                        ArrayList<Tag> filteredTags = new ArrayList<>();
                        for (Tag tag : tags) {
                            if (searchText.isEmpty() ||
                                tag.name.toLowerCase().contains(searchText) ||
                                tag.category.toString().toLowerCase().contains(searchText) ||
                                (tag.tooltip != null && tag.tooltip.toLowerCase().contains(searchText))) {
                                filteredTags.add(tag);
                            }
                        }

                        filteredTags.sort((a, b) -> a.name.compareToIgnoreCase(b.name));

                        // Store first visible tag
                        if (!filteredTags.isEmpty()) {
                            firstVisibleTag[0] = filteredTags.get(0);
                        }

                        int columnCount = 3;
                        int currentColumn = 0;

                        for (Tag tag : filteredTags) {
                            JButton tagButton = new JButton(tag.name);
                            tagButton.setToolTipText(tag.tooltip != null ? tag.tooltip : tag.category.toString());
                            tagButton.setFont(new Font("Inter", Font.PLAIN, 12));
                            tagButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
                            tagButton.setFocusPainted(false);
                            tagButton.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
                            tagButton.setContentAreaFilled(false);
                            tagButton.setBorderPainted(false);
                            tagButton.setOpaque(false);
                            tagButton.setForeground(new Color(55, 65, 81));

                            tagButton.addMouseListener(new java.awt.event.MouseAdapter() {
                                public void mouseEntered(java.awt.event.MouseEvent evt) {
                                    tagButton.setForeground(new Color(99, 102, 241));
                                }
                                public void mouseExited(java.awt.event.MouseEvent evt) {
                                    tagButton.setForeground(new Color(55, 65, 81));
                                }
                            });

                            tagButton.addActionListener(e -> {
                                generateTagActionListener(event, tag).actionPerformed(null);
                                lastTagUsed = tag.name;
                                findTagWindow.dispose();
                            });

                            gbc.gridx = currentColumn;
                            gbc.weightx = 1.0 / columnCount;
                            tagsPanel.add(tagButton, gbc);

                            currentColumn++;
                            if (currentColumn >= columnCount) {
                                currentColumn = 0;
                                gbc.gridy++;
                            }
                        }

                        if (filteredTags.isEmpty()) {
                            JLabel noResultsLabel = new JLabel("No tags found matching: " + searchText);
                            noResultsLabel.setForeground(new Color(156, 163, 175));
                            noResultsLabel.setFont(new Font("Inter", Font.PLAIN, 13));
                            gbc.gridx = 0;
                            gbc.gridwidth = columnCount;
                            tagsPanel.add(noResultsLabel, gbc);
                        }

                        tagsPanel.revalidate();
                        tagsPanel.repaint();
                    };

                    searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                        public void insertUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
                        public void removeUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
                        public void changedUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
                    });

                    searchField.addKeyListener(new KeyAdapter() {
                        @Override
                        public void keyPressed(KeyEvent e) {
                            if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                                findTagWindow.dispose();
                            } else if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                                if (firstVisibleTag[0] != null) {
                                    generateTagActionListener(event, firstVisibleTag[0]).actionPerformed(null);
                                    lastTagUsed = firstVisibleTag[0].name;
                                    findTagWindow.dispose();
                                }
                            }
                        }
                    });

                    findTagWindow.addWindowFocusListener(new java.awt.event.WindowAdapter() {
                        @Override
                        public void windowLostFocus(java.awt.event.WindowEvent e) {
                            findTagWindow.dispose();
                        }
                    });

                    mainPanel.add(searchPanel, BorderLayout.NORTH);
                    mainPanel.add(scrollPane, BorderLayout.CENTER);

                    findTagWindow.add(mainPanel);
                    findTagWindow.setSize(750, 500);
                    findTagWindow.setLocationRelativeTo(montoyaApi.userInterface().swingUtils().suiteFrame());

                    updateTags.run();

                    findTagWindow.setVisible(true);
                    searchField.requestFocusInWindow();
                });
            }),
            new HotkeyDefinition("Insert last tag", "Ctrl+Alt+I", event -> {
                if(lastTagUsed == null) {
                    return;
                }
                ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
                Tag tagObj = TagUtils.getTagByTagName(tags, lastTagUsed);
                generateTagActionListener(event, tagObj).actionPerformed(null);
            }),
            new HotkeyDefinition("New custom tag", "Ctrl+Alt+N", event -> CustomTags.showCreateEditTagDialog(false, null)),
            new HotkeyDefinition("List custom tags", "Ctrl+Alt+L", event -> CustomTags.showListTagsDialog()),
            new HotkeyDefinition("Global variables", "Ctrl+Alt+V", event -> Variables.showGlobalVariablesWindow()),
            new HotkeyDefinition("Tag Automator", "Ctrl+Alt+A", event -> TagAutomator.showRulesDialog()),
            new HotkeyDefinition("Settings", "Ctrl+Alt+S", event -> Settings.showSettingsWindow()),
            new HotkeyDefinition("Smart decode", "Ctrl+Alt+D", createAutoDecodeHandler()),
            new HotkeyDefinition("Show tag store", "Ctrl+Alt+T", event -> TagStore.showTagStore())
        );

        for (HotkeyDefinition hotkey : hotkeys) {
            registerHotkey(montoyaApi, burp, hotkey);
        }
    }

    private static class HotkeyDefinition {
        final String name;
        final String keyCombo;
        final HotKeyHandler handler;

        HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler) {
            this.name = name;
            this.keyCombo = keyCombo;
            this.handler = handler;
        }
    }

    private void registerHotkey(MontoyaApi montoyaApi, Burp burp, HotkeyDefinition hotkey) {
        Registration registration;

        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_WITH_NAME)) {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                HotKeyContext.HTTP_MESSAGE_EDITOR,
                HotKey.hotKey(hotkey.name, hotkey.keyCombo),
                hotkey.handler);
        } else {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                HotKeyContext.HTTP_MESSAGE_EDITOR,
                hotkey.keyCombo,
                hotkey.handler);
        }

        if(registration.isRegistered()) {
            montoyaApi.logging().logToOutput("Successfully registered hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
            if(hotkey.name.equals("Auto decode")) {
                hasHotKey = true;
            }
        } else {
            montoyaApi.logging().logToError("Failed to register hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
        }
    }

    private HotKeyHandler createAutoDecodeHandler() {
        return event -> {
            if (event.messageEditorRequestResponse().isEmpty()) {
                return;
            }
            MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().get();
            if(requestResponse.selectionOffsets().isPresent() &&
               requestResponse.selectionContext().toString().equalsIgnoreCase("request")) {
                String request = requestResponse.requestResponse().request().toString();
                int start = requestResponse.selectionOffsets().get().startIndexInclusive();
                int end = requestResponse.selectionOffsets().get().endIndexExclusive();
                String selectionWithTags = auto_decode_no_decrypt(request.substring(start, end));
                String modifiedRequest = request.substring(0, start) + selectionWithTags + request.substring(end);
                requestResponse.setRequest(HttpRequest.httpRequest(
                    requestResponse.requestResponse().httpService(), modifiedRequest));
            }
        };
    }
}
