package burp.hv.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.hv.*;
import burp.hv.ai.AI;
import burp.hv.ai.LearnFromRepeater;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.CustomTags;
import burp.hv.tags.TagAutomator;
import burp.hv.tags.Tag;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.hv.Convertors.auto_decode_no_decrypt;
import static burp.hv.HackvertorExtension.*;
import static burp.hv.tags.TagAutomator.getContextsFromRule;
import static burp.hv.tags.TagAutomator.shouldApplyRules;
import static burp.hv.utils.TagUtils.generateTagActionListener;

public class HackvertorContextMenu implements ContextMenuItemsProvider {
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        boolean allowTagCount;
        boolean sortTagCategories;
        boolean learnFromRepeater;
        boolean allowAiToGenerateCode;
        boolean tagsInProxy;
        try {
            learnFromRepeater = HackvertorExtension.generalSettings.getBoolean("learnFromRepeater");
            allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            allowTagCount = HackvertorExtension.generalSettings.getBoolean("allowTagCount");
            sortTagCategories = HackvertorExtension.generalSettings.getBoolean("sortTagCategories");
            tagsInProxy = HackvertorExtension.generalSettings.getBoolean("tagsInProxy");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }

        if (event.isFromTool(ToolType.PROXY) && !tagsInProxy) {
            JMenuItem tagsInProxyItem = new JMenuItem("Tags in the proxy are disabled");
            tagsInProxyItem.addActionListener(e -> HackvertorExtension.alert("You can enable them in Hackvertor->Settings->Allow tags in proxy"));
            menuItemList.add(tagsInProxyItem);
            return menuItemList;
        }
        switch (event.invocationType()) {
            //Intruder Context menu doesn't have the requestEditor unfortunately
            //case INTRUDER_PAYLOAD_POSITIONS:
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_VIEWER_REQUEST:
            case MESSAGE_VIEWER_RESPONSE:
            case SITE_MAP_TREE:
            case SITE_MAP_TABLE:
            case PROXY_HISTORY:
                break;
            default:
                return null;
        }

        JMenu menu = new JMenu("Hackvertor");
        Action hackvertorAction;
        if (event.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE) {
            hackvertorAction = new HackvertorAction("Send response body to Hackvertor", HackvertorExtension.extensionPanel, event);
        } else {
            hackvertorAction = new HackvertorAction("Send to Hackvertor", HackvertorExtension.extensionPanel, event);
        }
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction);
        menu.add(sendToHackvertor);

        TagAutomator.loadRules();
        JSONArray rules = TagAutomator.getRules();
        JMenu tagAutomationMenu = new JMenu("Apply Tag Automation");
        tagAutomationMenu.setEnabled(event.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE || event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST);
        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);
            ArrayList<String> contexts = getContextsFromRule(rule);
            boolean enabled = rule.optBoolean("enabled", true);
            if(!enabled) {
                continue;
            }
            if(!contexts.contains("response") && event.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE) {
                continue;
            }
            if(!contexts.contains("request") && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST) {
                continue;
            }

            if(!shouldApplyRules(contexts.contains("request") && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST ? "request" : "response",  getToolFromInvocationType(event.invocationType()),"Context Menu")) {
                continue;
            }

            JMenuItem ruleMenuItem = new JMenuItem(rule.getString("name"));
            ruleMenuItem.addActionListener(e -> {
                if(event.messageEditorRequestResponse().isPresent()) {
                    String ruleName = rule.getString("name");
                    if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST) {
                        HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                        String requestStr = request.toString();
                        String tool = getToolFromInvocationType(event.invocationType());
                        final String finalRequestStr = requestStr;
                        final String finalRuleName = ruleName;
                        try {
                            requestStr = HackvertorExtension.executorService.submit(() -> TagAutomator.applyRules(finalRequestStr, "request", tool, "Context Menu", finalRuleName)).get();
                        } catch (Exception ignored) {}
                        event.messageEditorRequestResponse().get().setRequest(HttpRequest.httpRequest(request.httpService(), requestStr));
                    }
                    if (event.invocationType() == InvocationType.MESSAGE_VIEWER_RESPONSE) {
                        HttpResponse response = event.messageEditorRequestResponse().get().requestResponse().response();
                        String responseStr = response.toString();
                        String tool = getToolFromInvocationType(event.invocationType());
                        final String finalResponseStr = responseStr;
                        final String finalRuleName = ruleName;
                        try {
                            responseStr = HackvertorExtension.executorService.submit(() -> TagAutomator.applyRules(finalResponseStr, "response", tool, "Context Menu", finalRuleName)).get();
                        } catch (Exception ignored) {}
                        HackvertorPanel hackvertorPanel = HackvertorExtension.extensionPanel.addNewPanel();
                        hackvertorPanel.getInputArea().setText(responseStr);
                        HackvertorExtension.extensionPanel.makeActiveBurpTab();
                    }
                }
            });
            tagAutomationMenu.add(ruleMenuItem);
        }

        menu.add(tagAutomationMenu);

        switch(event.invocationType()) {
            case SITE_MAP_TREE:
            case SITE_MAP_TABLE:
            case PROXY_HISTORY:
            case MESSAGE_VIEWER_REQUEST:
            case MESSAGE_VIEWER_RESPONSE:
                menuItemList.add(menu);
                return menuItemList;
        }

        JMenuItem insertLastTagMenuItem = new JMenuItem("Insert last tag");
        insertLastTagMenuItem.addActionListener(e -> {
            if(lastTagUsed == null) {
                return;
            }
            ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
            Tag tagObj = TagUtils.getTagByTagName(tags, lastTagUsed);
            generateTagActionListener(event, tagObj).actionPerformed(null);
        });
        menu.add(insertLastTagMenuItem);
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            String converted = HackvertorExtension.hackvertor.convert(event.messageEditorRequestResponse().get().requestResponse().request().toString(), HackvertorExtension.hackvertor);
            StringSelection stringSelection = new StringSelection(HttpRequest.httpRequest(event.messageEditorRequestResponse().get().requestResponse().httpService(), converted).url());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        });
        menu.add(copyUrl);

        JMenuItem convert = new JMenuItem("Convert tags");
        convert.addActionListener(e -> {
            if (event.messageEditorRequestResponse().isEmpty()) {
                return;
            }
            MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().get();
            if(!requestResponse.selectionContext().toString().equalsIgnoreCase("request")) {
                return;
            }
            if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || event.invocationType()  == InvocationType.MESSAGE_VIEWER_REQUEST) {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    event.messageEditorRequestResponse().get().setRequest(HttpRequest.httpRequest(request.httpService(), HackvertorExtension.hackvertor.convert(request.toString(), HackvertorExtension.hackvertor)));
                }
            }
        });
        menu.add(convert);
        JMenuItem clear = new JMenuItem("Clear tags");
        clear.addActionListener(e -> {
            if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || event.invocationType()  == InvocationType.MESSAGE_VIEWER_REQUEST) {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    event.messageEditorRequestResponse().get().setRequest(HttpRequest.httpRequest(request.httpService(), Hackvertor.removeHackvertorTags(request.toString())));
                }
            }
        });
        menu.add(clear);
        JMenuItem learnFromThisRequest = new JMenuItem("Learn encoding from this request");
        learnFromThisRequest.setEnabled(learnFromRepeater && AI.isAiSupported());
        learnFromThisRequest.addActionListener(e -> {
            if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || event.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST) {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(new HttpRequest[]{request});
                    LearnFromRepeater.learn(headersAndParameters, allowAiToGenerateCode);
                }
            }
        });
        menu.add(learnFromThisRequest);
        JMenuItem autodecodeConvert;
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        if(hasHotKey) {
            autodecodeConvert = new JMenuItem("Smart decode (CTRL+Alt+D)");
        } else {
            autodecodeConvert = new JMenuItem("Smart decode");
        }

        int start;
        int end;
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if(editor.isPresent() && editor.get().selectionOffsets().isPresent()) {
            start = editor.get().selectionOffsets().get().startIndexInclusive();
            end = editor.get().selectionOffsets().get().endIndexExclusive();
        } else {
            end = -1;
            start = -1;
        }

        autodecodeConvert.setEnabled(start != end);
        autodecodeConvert.addActionListener(e -> {
            if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || event.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST) {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    String requestStr = request.toString();
                    String convertedSelection = auto_decode_no_decrypt(requestStr.substring(start, end));
                    String modifiedRequest = "";
                    modifiedRequest += requestStr.substring(0, start);
                    modifiedRequest += convertedSelection;
                    modifiedRequest += requestStr.substring(end);
                    event.messageEditorRequestResponse().get().setRequest(HttpRequest.httpRequest(request.httpService(), modifiedRequest));
                }
            }
        });
        menu.add(autodecodeConvert);

        // Multi Encoder feature
        JMenuItem multiEncoder = new JMenuItem("Multi Encoder (Ctrl+Alt+M)");
        multiEncoder.setEnabled(start != end);
        multiEncoder.addActionListener(e -> {
            if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || event.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST) {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest request = event.messageEditorRequestResponse().get().requestResponse().request();
                    String requestStr = request.toString();
                    String selectedText = requestStr.substring(start, end);

                    // Get all available tags
                    ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();

                    // Show the Multi Encoder window
                    MultiEncoderWindow multiEncoderWindow = new MultiEncoderWindow(
                        montoyaApi,
                        selectedText,
                        tags,
                        event.messageEditorRequestResponse().get(),
                        event.messageEditorRequestResponse().get().requestResponse()
                    );
                    multiEncoderWindow.show();
                }
            }
        });
        menu.add(multiEncoder);

        menu.addSeparator();
        CustomTags.loadCustomTags();
        if(allowTagCount) {
            JMenu contextPopularTags = new JMenu("Popular tags for this context");
            ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
            String context = Utils.getContext(event.messageEditorRequestResponse().get().requestResponse().request());
            if(HackvertorExtension.contextTagCount.containsKey(context)) {
                if(HackvertorExtension.contextTagCount.get(context) != null) {
                    AtomicBoolean foundTags = new AtomicBoolean(false);
                    HackvertorExtension.contextTagCount.get(context).entrySet().stream().limit(HackvertorExtension.MAX_POPULAR_TAGS)
                            .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                            .forEach(entry -> {
                                JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "(" + entry.getValue() + ")");
                                Tag tagObj = TagUtils.getTagByTagName(tags, entry.getKey());
                                tagMenuItem.addActionListener(TagUtils.generateTagActionListener(event, tagObj));
                                contextPopularTags.add(tagMenuItem);
                                foundTags.set(true);
                            });
                    if(foundTags.get()) {
                        menu.add(contextPopularTags);
                    }
                }
            }
            JMenu popularTags = new JMenu("Popular tags");
            HackvertorExtension.tagCount.entrySet().stream().limit(HackvertorExtension.MAX_POPULAR_TAGS)
                    .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                    .forEach(entry -> {
                        JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "("+entry.getValue()+")");
                        Tag tagObj = TagUtils.getTagByTagName(tags, entry.getKey());
                        tagMenuItem.addActionListener(TagUtils.generateTagActionListener(event, tagObj));
                        popularTags.add(tagMenuItem);
                    });
            if(!HackvertorExtension.tagCount.isEmpty()) {
                menu.add(popularTags);
            }
        }
        List<String> categories = new ArrayList<>();
        for (Tag.Category category : Tag.Category.values()) {
            categories.add(category.name());
        }
        if(sortTagCategories) {
            Collections.sort(categories);
        }
        for (String category : categories) {
            JMenu categoryMenu = TagUtils.createTagMenuForCategory(HackvertorExtension.hackvertor.getTags(), Tag.Category.valueOf(category), event, "", false, null);
            menu.add(categoryMenu);
        }
        menuItemList.add(menu);
        return menuItemList;
    }
    
    private static String getToolFromInvocationType(InvocationType type) {
        switch(type) {
            case PROXY_HISTORY:
            case PROXY_INTERCEPT:
                return "Proxy";
            case INTRUDER_ATTACK_RESULTS:
            case INTRUDER_PAYLOAD_POSITIONS:
                return "Intruder";
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_VIEWER_REQUEST:
            case MESSAGE_EDITOR_RESPONSE:
            case MESSAGE_VIEWER_RESPONSE:
                return "Repeater";
            case SCANNER_RESULTS:
                return "Scanner";
            default:
                return "Extensions";
        }
    }
}
