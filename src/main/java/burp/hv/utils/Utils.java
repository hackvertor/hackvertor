package burp.hv.utils;

import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.hv.tags.CustomTags;
import burp.hv.tags.TagAutomator;
import burp.hv.settings.Settings;
import burp.hv.tags.TagStore;
import burp.hv.Variables;
import burp.hv.ui.HackvertorHistory;
import burp.hv.ui.HackvertorInput;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static burp.hv.HackvertorExtension.*;

public class Utils {

    public static String getContext(HttpRequest analyzedRequest) {
        try {
            if (analyzedRequest == null) {
                return null;
            }
            if (analyzedRequest.contentType() == ContentType.JSON) {
                return "JSON";
            }
            if (analyzedRequest.method() != null && analyzedRequest.method().equalsIgnoreCase("GET")) {
                return "GET";
            }
            if (analyzedRequest.method() != null && analyzedRequest.method().equalsIgnoreCase("POST")) {
                return "POST";
            }
            return null;
        } catch (Throwable ignored) {}
        return null;
    }

    public static void setMarginAndPadding(JComponent comp, int amount) {
        Border margin = new EmptyBorder(amount,amount,amount,amount);
        comp.setBorder(margin);
    }

    public static void openUrl(String url) {
        if(url.startsWith("https://")) {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (IOException ioException) {
                } catch (URISyntaxException uriSyntaxException) {

                }
            }
        }
    }

    public static String escapeChar(String input, String chr) {
        return input.replaceAll("(["+chr+"])", "\\\\$1");
    }

    public static void registerGeneralSettings(Settings settings) {
        settings.registerBooleanSetting("tagsInProxy", false, "Allow tags in Proxy", "Tag permissions", null);
        settings.registerBooleanSetting("tagsInIntruder", true, "Allow tags in Intruder", "Tag permissions", null);
        settings.registerBooleanSetting("tagsInRepeater", true, "Allow tags in Repeater", "Tag permissions", null);
        settings.registerBooleanSetting("tagsInScanner", true, "Allow tags in Scanner", "Tag permissions", null);
        settings.registerBooleanSetting("tagsInExtensions", true, "Allow tags in Extensions", "Tag permissions", null);
        settings.registerBooleanSetting("tagsInResponse", false, "Allow tags in HTTP response", "Tag permissions", null);
        settings.registerBooleanSetting("codeExecutionTagsEnabled", false, "Allow code execution tags", "Tag permissions", "Using code execution tags on untrusted requests can compromise your system, are you sure?");
        settings.registerBooleanSetting("autoUpdateContentLength", true, "Auto update content length", "Requests", null);
        settings.registerIntegerSetting("maxBodyLength", 3 * 1024 * 1024, "Maximum body length", "Requests");
        settings.registerBooleanSetting("allowTagCount", true, "Count tag usage (Not sent to any server)","Statistics", null);
        settings.registerBooleanSetting("allowAiToGenerateCode", false, "Use AI to generate code", "AI", "Using AI to generate code execution tags can compromise your system, be careful when using it with untrusted repeater requests. Are you sure?");
        settings.registerBooleanSetting("allowAiToSummariseCode", false, "Use AI to summarise custom tags code", "AI", null);
        settings.registerBooleanSetting("allowAiTags", false, "Use AI in tags", "AI", null);
        settings.registerBooleanSetting("debugAi", false, "Debug AI requests", "AI", null);
        settings.registerBooleanSetting("learnFromRepeater", false, "Use AI to learn from repeater", "AI", "This is experimental. It will send your entire repeater requests to the AI in order to learn encodings. Are you sure you want to enable this?");
        settings.registerBooleanSetting("sortTagCategories", true, "Alphabetically sort tag categories", "Misc", null);
        settings.registerBooleanSetting("allowAutoConvertClipboard", false, "Auto convert clipboard","Misc", null);
        settings.registerBooleanSetting("showOutputInMessageEditor", false, "Show the output panel in the message editor","Misc", null);
        settings.registerStringSetting("pythonModulePath", "", "Python module path","System");
    }

    public static JFrame getHackvertorWindowInstance() {
        if(HackvertorFrame != null) {
            return HackvertorFrame;
        }
        HackvertorFrame = new JFrame();
        HackvertorFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                HackvertorFrame.setVisible(false);
                HackvertorFrame.getContentPane().removeAll();
                HackvertorFrame.getContentPane().setLayout(new BorderLayout());
            }
        });
        return HackvertorFrame;
    }

    public static JMenu generateHackvertorMenuBar() {
        JMenu hvMenuBar = new JMenu("Hackvertor");
        JMenuItem createCustomTagsMenu = new JMenuItem("Create custom tag");
        createCustomTagsMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CustomTags.showCreateEditTagDialog(false, null);
            }
        });
        JMenuItem listCustomTagsMenu = new JMenuItem("List custom tags");
        listCustomTagsMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                CustomTags.showListTagsDialog();
            }
        });
        JMenuItem tagStoreMenu = new JMenuItem("View tag store");
        tagStoreMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                TagStore.showTagStore();
            }
        });
        JMenuItem globalVariablesMenu = new JMenuItem("Global variables");
        globalVariablesMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Variables.showGlobalVariablesWindow();
            }
        });
        JMenuItem tagAutomatorMenu = new JMenuItem("Tag Automator");
        tagAutomatorMenu.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                TagAutomator.showRulesDialog();
            }
        });
        hvMenuBar.add(createCustomTagsMenu);
        hvMenuBar.add(listCustomTagsMenu);
        hvMenuBar.add(globalVariablesMenu);
        hvMenuBar.add(tagAutomatorMenu);
        hvMenuBar.addSeparator();
        hvMenuBar.add(tagStoreMenu);
        JMenuItem settingsMenu = new JMenuItem("Settings");
        settingsMenu.addActionListener(e -> Settings.showSettingsWindow());
        hvMenuBar.addSeparator();
        hvMenuBar.add(settingsMenu);
        hvMenuBar.addSeparator();
        JMenuItem reportBugMenu = new JMenuItem("Report bug/request feature");
        reportBugMenu.addActionListener(e -> {
            Utils.openUrl("https://github.com/hackvertor/hackvertor/issues/new");
        });
        hvMenuBar.add(reportBugMenu);
        return hvMenuBar;
    }

    public static void configureTextArea(HackvertorInput area) {
        area.setLineWrap(true);
        callbacks.customizeUiComponent(area);
    }

    public static boolean hasApiMethod(Object obj, String methodName) {
        try {
            Class<?> clazz = obj.getClass();
            clazz.getMethod(methodName);
            return true;
        } catch(NoSuchMethodException e){
            return false;
        }
    }
 }
