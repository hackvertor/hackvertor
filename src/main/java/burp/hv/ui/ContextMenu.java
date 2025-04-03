package burp.hv.ui;

import burp.*;
import burp.hv.*;
import burp.hv.ai.AI;
import burp.hv.ai.LearnFromRepeater;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.CustomTags;
import burp.hv.tags.Tag;
import burp.hv.utils.TagUtils;
import burp.hv.utils.UrlUtils;
import burp.hv.utils.Utils;
import org.json.JSONArray;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static burp.hv.Convertors.auto_decode_no_decrypt;
import static burp.hv.HackvertorExtension.*;

public class ContextMenu implements IContextMenuFactory {
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        int[] bounds = invocation.getSelectionBounds();
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
                break;
            default:
                return null;
        }
        boolean allowTagCount;
        boolean sortTagCategories;
        boolean learnFromRepeater;
        boolean allowAiToGenerateCode;
        try {
            learnFromRepeater = HackvertorExtension.generalSettings.getBoolean("learnFromRepeater");
            allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            allowTagCount = HackvertorExtension.generalSettings.getBoolean("allowTagCount");
            sortTagCategories = HackvertorExtension.generalSettings.getBoolean("sortTagCategories");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }

        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenu submenu = new JMenu("Hackvertor");
        Action hackvertorAction;
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE && bounds != null && bounds[0] == bounds[1]) {
            hackvertorAction = new HackvertorAction("Send response body to Hackvertor", HackvertorExtension.extensionPanel, invocation);
        } else {
            hackvertorAction = new HackvertorAction("Send to Hackvertor", HackvertorExtension.extensionPanel, invocation);
        }
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction);
        submenu.add(sendToHackvertor);

        switch(invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                menu.add(submenu);
                return menu;
        }

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            String converted = HackvertorExtension.hackvertor.convert(HackvertorExtension.helpers.bytesToString(invocation.getSelectedMessages()[0].getRequest()), null);
            URL url = HackvertorExtension.helpers.analyzeRequest(invocation.getSelectedMessages()[0].getHttpService(), HackvertorExtension.helpers.stringToBytes(converted)).getUrl();
            StringSelection stringSelection = null;
            stringSelection = new StringSelection(UrlUtils.buildUrl(url));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        });
        submenu.add(copyUrl);

        JMenuItem convert = new JMenuItem("Convert tags");
        convert.addActionListener(e -> {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                invocation.getSelectedMessages()[0].setRequest(HackvertorExtension.helpers.stringToBytes(HackvertorExtension.hackvertor.convert(HackvertorExtension.helpers.bytesToString(message), null)));
            }
        });
        submenu.add(convert);
        JMenuItem learnFromThisRequest = new JMenuItem("Learn encoding from this request");
        learnFromThisRequest.setEnabled(learnFromRepeater && AI.isAiSupported());
        learnFromThisRequest.addActionListener(e -> {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                IHttpRequestResponse messageInfo = invocation.getSelectedMessages()[0];
                if(messageInfo.getHttpService() != null && messageInfo.getRequest() != null) {
                    IRequestInfo currentRequest = HackvertorExtension.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                    JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(new IRequestInfo[]{currentRequest});
                    LearnFromRepeater.learn(headersAndParameters, allowAiToGenerateCode);
                }
            }
        });
        submenu.add(learnFromThisRequest);
        JMenuItem autodecodeConvert;
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        if(hasHotKey) {
            autodecodeConvert = new JMenuItem("Smart decode (CTRL+Alt+D)");
        } else {
            autodecodeConvert = new JMenuItem("Smart decode");
        }
        autodecodeConvert.setEnabled(bounds != null && bounds[0] != bounds[1]);
        autodecodeConvert.addActionListener(e -> {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                byte[] selection = Arrays.copyOfRange(message, bounds[0], bounds[1]);
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    byte[] convertedSelection = HackvertorExtension.helpers.stringToBytes(auto_decode_no_decrypt(HackvertorExtension.helpers.bytesToString(selection)));
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
        submenu.add(autodecodeConvert);
        submenu.addSeparator();
        CustomTags.loadCustomTags();
        if(allowTagCount) {
            JMenu contextPopularTags = new JMenu("Popular tags for this context");
            ArrayList<Tag> tags = HackvertorExtension.hackvertor.getTags();
            byte[] message = invocation.getSelectedMessages()[0].getRequest();
            IRequestInfo analyzedRequest = HackvertorExtension.helpers.analyzeRequest(message);
            String context = Utils.getContext(analyzedRequest);
            if(HackvertorExtension.contextTagCount.containsKey(context)) {
                if(HackvertorExtension.contextTagCount.get(context) != null) {
                    AtomicBoolean foundTags = new AtomicBoolean(false);
                    HackvertorExtension.contextTagCount.get(context).entrySet().stream().limit(HackvertorExtension.MAX_POPULAR_TAGS)
                            .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                            .forEach(entry -> {
                                JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "(" + entry.getValue() + ")");
                                Tag tagObj = TagUtils.getTagByTagName(tags, entry.getKey());
                                tagMenuItem.addActionListener(TagUtils.generateTagActionListener(invocation, tagObj));
                                contextPopularTags.add(tagMenuItem);
                                foundTags.set(true);
                            });
                    if(foundTags.get()) {
                        submenu.add(contextPopularTags);
                    }
                }
            }
            JMenu popularTags = new JMenu("Popular tags");
            HackvertorExtension.tagCount.entrySet().stream().limit(HackvertorExtension.MAX_POPULAR_TAGS)
                    .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                    .forEach(entry -> {
                        JMenuItem tagMenuItem = new JMenuItem(entry.getKey() + "("+entry.getValue()+")");
                        Tag tagObj = TagUtils.getTagByTagName(tags, entry.getKey());
                        tagMenuItem.addActionListener(TagUtils.generateTagActionListener(invocation, tagObj));
                        popularTags.add(tagMenuItem);
                    });
            if(!HackvertorExtension.tagCount.isEmpty()) {
                submenu.add(popularTags);
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
            JMenu categoryMenu = TagUtils.createTagMenuForCategory(HackvertorExtension.hackvertor.getTags(), Tag.Category.valueOf(category), invocation, "", false, null);
            submenu.add(categoryMenu);
        }
        menu.add(submenu);
        return menu;
    }
}
