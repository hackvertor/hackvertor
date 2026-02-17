package burp.hv.tags;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.hv.HackvertorExtension;
import burp.hv.ui.HackvertorInput;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;

import static burp.hv.HackvertorExtension.montoyaApi;

public class TagStore {
    public static void showTagStore() {
        final String TAG_STORE_URL = "https://raw.githubusercontent.com/hackvertor/hackvertor/master/tag-store/";
        //final String TAG_STORE_URL = "http://127.0.0.1:4000/";
        String jsonResponse = makeHttpRequest(TAG_STORE_URL + "tag-store.json", "GET");
        if(jsonResponse == null) {
            HackvertorExtension.callbacks.printError("Unable to load tag store JSON");
            HackvertorExtension.alert("Unable to load the tag store. Store may be down.");
            return;
        }
        JSONArray tagStore;
        try {
            tagStore = new JSONArray(jsonResponse);
        } catch (JSONException ex) {
            HackvertorExtension.alert("Unable to load the tag store. Store may be down.");
            HackvertorExtension.callbacks.printError("Invalid JSON");
            return;
        }

        if(tagStore.isEmpty()) {
            HackvertorExtension.alert("Unable to load the tag store. Tag store JSON not found.");
            HackvertorExtension.callbacks.printError("Unable to retrieve JSON");
            return;
        }
        HashMap<String, String> storeCode = new HashMap<>();
        JFrame tagStoreWindow = Utils.getHackvertorWindowInstance();
        tagStoreWindow.getContentPane().removeAll();
        tagStoreWindow.getContentPane().setLayout(new BorderLayout());
        tagStoreWindow.setTitle("Hackvertor tag store");
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
            tagStoreWindow.setVisible(false);
            tagStoreWindow.getContentPane().removeAll();
        });
        Utils.setMarginAndPadding(closeButton, 10);
        Utils.setMarginAndPadding(installButton, 10);
        optionsPanel.add(title, BorderLayout.NORTH);
        JTextComponent.removeKeymap("RTextAreaKeymap");
        HackvertorInput codeArea = new HackvertorInput();
        codeArea.setEditable(false);
        codeArea.setLineWrap(true);
        codeArea.setText("Code goes here");
        JScrollPane codeScroller = new JScrollPane(codeArea);
        Utils.setMarginAndPadding(codeScroller, 10);
        JTextArea description = new JTextArea("Description goes here");
        description.setEditable(false);
        description.setLineWrap(true);
        description.setRows(4);
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
            HackvertorExtension.alert("Custom tags can compromise your system. Please ensure you've evaluated the code before you install it.");
            int confirm = JOptionPane.showConfirmDialog(tagStoreWindow, "Are you sure you want to install this custom tag?");
            if(confirm == 0) {
                int selectedRow = storeTable.getSelectedRow();
                String tagName = (String) storeTable.getValueAt(selectedRow, 0);
                if (!TagUtils.validateTagName(tagName)) {
                    HackvertorExtension.alert("Invalid tag name. Use a-zA-Z_0-9 for tag names");
                    return;
                }
                String code = storeCode.get(tagName);
                JSONObject tag = storeTags.get(tagName);
                int numberOfArgs = tag.getInt("numberOfArgs");
                String language = tag.getString("language");
                if (!TagUtils.validateCodeLength(code)) {
                    HackvertorExtension.alert("Invalid code unable to install tag. Code cannot be blank");
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
                    if (!TagUtils.validateParam(argument1)) {
                        HackvertorExtension.alert("Invalid param name. For argument1. Use " + TagUtils.paramRegex);
                        return;
                    }
                    if (argument1Type.equals("Number") && !TagUtils.validateTagParamNumber(argument1Default)) {
                        HackvertorExtension.alert("Invalid default value for argument1. Use " + TagUtils.numberRegex);
                        return;
                    }
                    if (!TagUtils.validateParam(argument2)) {
                        HackvertorExtension.alert("Invalid param name for argument2. Use " + TagUtils.paramRegex);
                        return;
                    }
                    if (argument2Type.equals("Number") && !TagUtils.validateTagParamNumber(argument2Default)) {
                        HackvertorExtension.alert("Invalid default value for argument2. Use " + TagUtils.numberRegex);
                        return;
                    }
                }
                CustomTags.loadCustomTags();
                if(HackvertorExtension.hackvertor.hasCustomTag(tagName)) {
                    CustomTags.updateCustomTag( "_" + tagName, language, code, argument1, argument1Type, argument1Default, argument2, argument2Type, argument2Default, numberOfArgs);
                } else {
                    CustomTags.createCustomTag(tagName, language, code, argument1, argument1Type, argument1Default, argument2, argument2Type, argument2Default, numberOfArgs);
                }
                CustomTags.loadCustomTags();
                HackvertorExtension.alert("Successfully installed the tag");
            }
        });
        selectionModel.addListSelectionListener(e -> {
            if(e.getValueIsAdjusting()) {
                return;
            }
            int selectedRow = storeTable.getSelectedRow();
            String tagName = (String) storeTable.getValueAt(selectedRow, 0);
            tagName = TagUtils.sanitizeTagName(tagName);
            String code = null;
            CustomTags.loadCustomTags();
            if(HackvertorExtension.hackvertor.hasCustomTag(tagName)) {
                installButton.setEnabled(false);
            } else {
                installButton.setEnabled(true);
            }

            if(storeCode.containsKey(tagName)) {
                code = storeCode.get(tagName);
            } else {
                code = makeHttpRequest(TAG_STORE_URL+tagName+"/"+tagName+ TagUtils.getExtensionFromLanguage(storeTags.get(tagName).getString("language")), "GET");
                if(code == null) {
                    HackvertorExtension.callbacks.printError("Unable get retrieve code for tag:"+tagName);
                    return;
                }
                storeCode.put(tagName, code);
            }
            title.setText(tagName);
            description.setText(storeTags.get(tagName).getString("description"));
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
        Utils.makeWindowVisible(tagStoreWindow);
    }

    public static String makeHttpRequest(String requestUrl, String method) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(requestUrl);
            request = request.withAddedHeader("Content-Type", "application/json");
            request = request.withMethod(method);
            final HttpRequest finalRequest = request;
            RequestOptions options = RequestOptions.requestOptions()
                    .withUpstreamTLSVerification();
            return HackvertorExtension.executorService.submit(() -> montoyaApi.http().sendRequest(finalRequest, options).response().bodyToString()).get();
        } catch (Throwable ex) {
            montoyaApi.logging().logToError("Error making request", ex);
        }
        return null;
    }
}
