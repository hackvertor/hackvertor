package burp.hv;

import burp.*;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
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
    public static String version = "v2.2.42";
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
    public static boolean isDarkTheme = false;

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
        JOptionPane.showMessageDialog(KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusedWindow(), msg);
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
        montoyaApi.logging().logToOutput(extensionName + " " + version);
        HackvertorExtension.montoyaApi = montoyaApi;
        isDarkTheme = montoyaApi.userInterface().currentTheme().equals(Theme.DARK);
        montoyaApi.userInterface().menuBar().registerMenu(Utils.generateHackvertorMenuBar());
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        montoyaApi.http().registerHttpHandler(new HackvertorHttpHandler());
        montoyaApi.websockets().registerWebSocketCreatedHandler(new HackvertorWebSocketHandler());
        montoyaApi.userInterface().registerContextMenuItemsProvider(new HackvertorContextMenu());

        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
            registerAllHotkeys(montoyaApi, burp);
        }
    }

    private void registerAllHotkeys(MontoyaApi montoyaApi, Burp burp) {
        List<HotkeyDefinition> hotkeys = Arrays.asList(
            new HotkeyDefinition("Convert", "Ctrl+Alt+H", event -> {
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
                ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
                TagFinderWindow finderWindow = new TagFinderWindow(montoyaApi, event, tags,
                    (tagName, window) -> { /* Callback handled internally */ });
                finderWindow.show();
            }),
            new HotkeyDefinition("Insert last tag", "Ctrl+Alt+I", event -> {
                if(lastTagUsed == null) {
                    return;
                }
                ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
                Tag tagObj = TagUtils.getTagByTagName(tags, lastTagUsed);
                generateTagActionListener(event, tagObj).actionPerformed(null);
            }),
            new HotkeyDefinition("Smart decode", "Ctrl+Alt+D", createSmartDecodeHandler()),
            new HotkeyDefinition("Multi Encoder", "Ctrl+Alt+M", createMultiEncoderHandler(montoyaApi)),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("New custom tag", "Ctrl+Alt+N", event -> CustomTags.showCreateEditTagDialog(false, null))
                : new HotkeyDefinition("New custom tag", "Ctrl+Alt+N", event -> CustomTags.showCreateEditTagDialog(false, null)),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("List custom tags", "Ctrl+Alt+L", event -> CustomTags.showListTagsDialog())
                : new HotkeyDefinition("List custom tags", "Ctrl+Alt+L", event -> CustomTags.showListTagsDialog()),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("Global variables", "Ctrl+Alt+V", event -> Variables.showGlobalVariablesWindow())
                : new HotkeyDefinition("Global variables", "Ctrl+Alt+V", event -> Variables.showGlobalVariablesWindow()),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("Tag Automator", "Ctrl+Alt+A", event -> TagAutomator.showRulesDialog())
                : new HotkeyDefinition("Tag Automator", "Ctrl+Alt+A", event -> TagAutomator.showRulesDialog()),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("Settings", "Ctrl+Alt+S", event -> Settings.showSettingsWindow())
                : new HotkeyDefinition("Settings", "Ctrl+Alt+S", event -> Settings.showSettingsWindow()),
            burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_IN_ALL_CONTEXTS)
                ? HotkeyDefinition.forAllContexts("Show tag store", "Ctrl+Alt+T", event -> TagStore.showTagStore())
                : new HotkeyDefinition("Show tag store", "Ctrl+Alt+T", event -> TagStore.showTagStore())
        );

        for (HotkeyDefinition hotkey : hotkeys) {
            registerHotkey(montoyaApi, burp, hotkey);
        }
    }

    private static class HotkeyDefinition {
        final String name;
        final String keyCombo;
        final HotKeyHandler handler;
        final HotKeyContext[] contexts;
        final boolean allContexts;

        HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler) {
            this(name, keyCombo, handler, HotKeyContext.HTTP_MESSAGE_EDITOR);
        }

        HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler, HotKeyContext... contexts) {
            this.name = name;
            this.keyCombo = keyCombo;
            this.handler = handler;
            this.contexts = contexts;
            this.allContexts = false;
        }

        static HotkeyDefinition forAllContexts(String name, String keyCombo, HotKeyHandler handler) {
            return new HotkeyDefinition(name, keyCombo, handler, true);
        }

        private HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler, boolean allContexts) {
            this.name = name;
            this.keyCombo = keyCombo;
            this.handler = handler;
            this.contexts = null;
            this.allContexts = allContexts;
        }
    }

    private void registerHotkey(MontoyaApi montoyaApi, Burp burp, HotkeyDefinition hotkey) {
        if (hotkey.allContexts) {
            Registration registration = montoyaApi.userInterface().registerHotKeyHandler(
                HotKey.hotKey(hotkey.name, hotkey.keyCombo),
                hotkey.handler);
            if (registration.isRegistered()) {
                montoyaApi.logging().logToOutput("Successfully registered hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ") for all contexts");
            } else {
                montoyaApi.logging().logToError("Failed to register hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ") for all contexts");
            }
            return;
        }

        for (HotKeyContext context : hotkey.contexts) {
            Registration registration;
            if (burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_WITH_NAME)) {
                registration = montoyaApi.userInterface().registerHotKeyHandler(
                    context,
                    HotKey.hotKey(hotkey.name, hotkey.keyCombo),
                    hotkey.handler);
            } else {
                registration = montoyaApi.userInterface().registerHotKeyHandler(
                    context,
                    hotkey.keyCombo,
                    hotkey.handler);
            }

            if (registration.isRegistered()) {
                montoyaApi.logging().logToOutput("Successfully registered hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ") for context: " + context);
                if (hotkey.name.equals("Auto decode")) {
                    hasHotKey = true;
                }
            } else {
                montoyaApi.logging().logToError("Failed to register hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ") for context: " + context);
            }
        }
    }

    private HotKeyHandler createSmartDecodeHandler() {
        return event -> {
            if (event.messageEditorRequestResponse().isEmpty()) {
                return;
            }
            MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().get();
            if (!requestResponse.selectionContext().toString().equalsIgnoreCase("request")) {
                return;
            }
            String request = requestResponse.requestResponse().request().toString();
            String modifiedRequest;
            if (requestResponse.selectionOffsets().isPresent()) {
                int start = requestResponse.selectionOffsets().get().startIndexInclusive();
                int end = requestResponse.selectionOffsets().get().endIndexExclusive();
                if (start != end) {
                    String decoded = auto_decode_no_decrypt(request.substring(start, end));
                    modifiedRequest = request.substring(0, start) + decoded + request.substring(end);
                } else {
                    modifiedRequest = auto_decode_partial(request);
                }
            } else {
                modifiedRequest = auto_decode_partial(request);
            }
            requestResponse.setRequest(HttpRequest.httpRequest(
                requestResponse.requestResponse().httpService(), modifiedRequest));
        };
    }

    private HotKeyHandler createMultiEncoderHandler(MontoyaApi montoyaApi) {
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

                if (start != end) {
                    String selectedText = request.substring(start, end);
                    ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();

                    // Show the Multi Encoder window
                    MultiEncoderWindow multiEncoderWindow = new MultiEncoderWindow(
                        montoyaApi,
                        selectedText,
                        tags,
                        requestResponse,
                        requestResponse.requestResponse()
                    );
                    multiEncoderWindow.show();
                }
            }
        };
    }
}
