package burp.hv.utils;

import burp.IContextMenuInvocation;
import burp.IRequestInfo;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.hv.Convertors;
import burp.hv.HackvertorExtension;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.tags.Tag;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.ui.MenuScroller;
import burp.parser.Element;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static burp.hv.Convertors.auto_decode_no_decrypt;
import static burp.hv.HackvertorExtension.*;

public class TagUtils {
    public static String paramRegex = "^[a-zA-Z_]\\w{0,100}$";
    public static String numberRegex = "^(?:0x[a-fA-F0-9]+|\\d+)$";
    public static String tagNameRegex = "[^\\w]";

    public static JScrollPane createButtons(List<Tag> tags, final JTextArea inputArea, Tag.Category displayCategory, String searchTag, Boolean regex) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JScrollPane scrollFrame = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        for (final Tag tagObj : tags) {
            final JButton btn = new JButton(tagObj.name);
            btn.setFocusable(false);
            btn.setToolTipText(tagObj.tooltip);

            if ((displayCategory != null && displayCategory.equals(tagObj.category)) || (StringUtils.isNotEmpty(searchTag) && (regex ? Pattern.compile(searchTag).matcher(tagObj.name).find() : tagObj.name.contains(searchTag)))) {
                btn.putClientProperty("tag", tagObj);
                btn.addActionListener(e -> {
                    String selectedText = inputArea.getSelectedText();
                    if (selectedText == null) {
                        selectedText = "";
                    }
                    String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                    String tagStart = tagStartEnd[0];
                    String tagEnd = tagStartEnd[1];
                    String replacedText = tagStart + selectedText + tagEnd;
                    int start = inputArea.getSelectionStart();
                    int end = start + replacedText.length();
                    inputArea.replaceSelection(replacedText);
                    inputArea.select(start + tagStart.length(), end - tagEnd.length());
                    int selectionStart = inputArea.getSelectionStart();
                    int selectionEnd = inputArea.getSelectionEnd();
                    Highlighter.Highlight[] highlights = inputArea.getHighlighter().getHighlights();
                    for (Highlighter.Highlight highlight : highlights) {
                        int highlightStart = highlight.getStartOffset();
                        int highlightEnd = highlight.getEndOffset();
                        if ((highlightStart < selectionEnd && highlightEnd > selectionStart)) {
                            continue;
                        }
                        inputArea.select(highlight.getStartOffset(), highlight.getEndOffset());
                        selectedText = inputArea.getSelectedText();
                        if (selectedText != null) {
                            tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                            tagStart = tagStartEnd[0];
                            tagEnd = tagStartEnd[1];
                            inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                        }
                    }
                });
                panel.add(btn);
            }
        }
        return scrollFrame;
    }

    public static String elementSequenceToString(List<Element> elements){
        return elements.stream().map(Objects::toString).collect(Collectors.joining());
    }

    public static Tag getTagByTagName(Collection<Tag> tags, String tagName) {
        return tags.stream().filter(tag -> tagName.equals(tag.name)).findFirst().orElse(null);
    }

    public static ActionListener generateTagActionListener(final HotKeyEvent event, Tag tagObj) {
        return e -> applyTagToEvent(event.messageEditorRequestResponse(), tagObj, true);
    }

    public static ActionListener generateTagActionListener(final ContextMenuEvent event, Tag tagObj) {
        return e -> {
            boolean isValidInvocation = event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST ||
                                       event.invocationType() == InvocationType.MESSAGE_VIEWER_REQUEST ||
                                       event.invocationType() == InvocationType.INTRUDER_PAYLOAD_POSITIONS;
            if (isValidInvocation) {
                applyTagToEvent(event.messageEditorRequestResponse(), tagObj, false);
            }
        };
    }

    private static void applyTagToEvent(Optional<MessageEditorHttpRequestResponse> editorOpt, Tag tagObj, boolean isHotKey) {
        if (!editorOpt.isPresent()) {
            return;
        }

        MessageEditorHttpRequestResponse editor = editorOpt.get();

        boolean allowTagCount;
        try {
            allowTagCount = generalSettings.getBoolean("allowTagCount");
        } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
            callbacks.printError("Error loading settings:" + ex);
            throw new RuntimeException(ex);
        }

        String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
        String tagStart = tagStartEnd[0];
        String tagEnd = tagStartEnd[1];

        int start;
        int end;
        if (editor.selectionOffsets().isPresent()) {
            start = editor.selectionOffsets().get().startIndexInclusive();
            end = editor.selectionOffsets().get().endIndexExclusive();
        } else {
            start = editor.caretPosition();
            end = editor.caretPosition();
        }

        if(allowTagCount) {
            String context = Utils.getContext(editor.requestResponse().request());
            if(contextTagCount.containsKey(context)) {
                int currentCount = contextTagCount.get(context).get(tagObj.name) == null ? 0 : contextTagCount.get(context).get(tagObj.name);
                contextTagCount.get(context).put(tagObj.name, currentCount + 1);
            }

            int count = tagCount.get(tagObj.name) == null ? 0 : tagCount.get(tagObj.name);
            tagCount.put(tagObj.name, count + 1);
        }

        HttpRequest request = editor.requestResponse().request();
        String requestStr = request.toString();
        String selection = requestStr.substring(start, end);
        String modifiedRequest = "";
        modifiedRequest += requestStr.substring(0, start);
        modifiedRequest += tagStart;
        modifiedRequest += selection;
        modifiedRequest += tagEnd;
        modifiedRequest += requestStr.substring(end);
        editor.setRequest(HttpRequest.httpRequest(request.httpService(), modifiedRequest));
        lastTagUsed = tagObj.name;
    }

    public static JMenu createTagMenuForCategory(List<Tag> tags, Tag.Category category, final ContextMenuEvent event, String searchTag, Boolean regex, Tag specificTag) {
        JMenu parentMenu = new JMenu(category.name());
        int tagCount = (int) tags.stream().filter(tag -> tag.category == category).count();
        if (tagCount > 40) {
            JMenu numberMenu = new JMenu("0-9");
            MenuScroller.setScrollerFor(numberMenu);
            parentMenu.add(numberMenu);
            for (char c = 'a'; c <= 'z'; c++) {
                JMenu letterMenu = new JMenu(String.valueOf(c));
                MenuScroller.setScrollerFor(letterMenu);
                parentMenu.add(letterMenu);
            }
        }

        for (final Tag tagObj : tags) {
            final JMenuItem menu = new JMenuItem(tagObj.name);
            menu.setToolTipText(tagObj.tooltip);
            if ((category != null && category.equals(tagObj.category)) || (searchTag.length() > 0 && (regex ? tagObj.name.matches(searchTag) : tagObj.name.contains(searchTag)))) {
                menu.addActionListener(generateTagActionListener(event, tagObj));
                if (tagCount > 40) {
                    for (int i = 0; i < parentMenu.getItemCount(); i++) {
                        if (parentMenu.getItem(i).getText().equals("0-9") && Character.isDigit(tagObj.name.charAt(0))) {
                            parentMenu.getItem(i).add(menu);
                        } else if (tagObj.name.toLowerCase().startsWith(parentMenu.getItem(i).getText())) {
                            parentMenu.getItem(i).add(menu);
                        }
                    }
                } else {
                    parentMenu.add(menu);
                }
            }
        }
        return parentMenu;
    }

    public static String sanitizeTagName(String tagName) {
        return tagName.replaceAll(tagNameRegex, "");
    }

    public static Boolean validateParam(String param) {
        return param.matches(paramRegex);
    }

    public static Boolean validateCode(String code) {
        return !code.isEmpty();
    }

    public static Boolean validateCodeLength(String code) {
        return !code.isEmpty();
    }

    public static Boolean isValidTagName(String tagName) {
        return tagName.matches("^[\\w-]+$");
    }

    public static Boolean validateTagName(String code) {
        code = sanitizeTagName(code);
        return !code.isEmpty();
    }

    public static Boolean validateTagParamNumber(String tagParamNumber) {
        return tagParamNumber.matches(numberRegex);
    }

    public static String getExtensionFromLanguage(String language) {
        switch (language) {
            case "AI":
                return ".ai";
            case "Python":
                return ".py";
            case "JavaScript":
                return ".js";
            case "Java":
                return ".java";
            case "Groovy":
                return ".groovy";
            default:
                return null;
        }
    }

    public static boolean shouldProcessTags(ToolType toolType) {
        boolean tagsInProxy;
        boolean tagsInIntruder;
        boolean tagsInRepeater;
        boolean tagsInScanner;
        boolean tagsInExtensions;

        try {
            tagsInProxy = HackvertorExtension.generalSettings.getBoolean("tagsInProxy");
            tagsInIntruder = HackvertorExtension.generalSettings.getBoolean("tagsInIntruder");
            tagsInRepeater = HackvertorExtension.generalSettings.getBoolean("tagsInRepeater");
            tagsInScanner = HackvertorExtension.generalSettings.getBoolean("tagsInScanner");
            tagsInExtensions = HackvertorExtension.generalSettings.getBoolean("tagsInExtensions");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
        switch (toolType) {
            case PROXY:
                if (!tagsInProxy) {
                    return false;
                }
                break;
            case INTRUDER:
                if (!tagsInIntruder) {
                    return false;
                }
                break;
            case REPEATER:
                if (!tagsInRepeater) {
                    return false;
                }
                break;
            case SCANNER:
                if (!tagsInScanner) {
                    return false;
                }
                break;
            case EXTENSIONS:
                if (!tagsInExtensions) {
                    return false;
                }
                break;
            default:
                return false;
        }
        return true;
    }
}
