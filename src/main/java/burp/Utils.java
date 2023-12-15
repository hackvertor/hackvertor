package burp;

import burp.parser.Element;
import burp.ui.HackvertorInput;
import burp.ui.MenuScroller;
import com.github.javafaker.Bool;
import org.apache.commons.lang3.StringUtils;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static burp.BurpExtender.*;

public class Utils {
    public static String paramRegex = "^[a-zA-Z_]\\w{0,10}$";
    public static String numberRegex = "^(?:0x[a-fA-F0-9]+|\\d+)$";
    public static String tagNameRegex = "[^\\w]";
    public static final int MAX_TAG_CODE_LEN = 1337;
    public static JScrollPane createButtons(List<Tag> tags, final JTextArea inputArea, Tag.Category displayCategory, String searchTag, Boolean regex) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JScrollPane scrollFrame = new JScrollPane(panel, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        for (final Tag tagObj : tags) {
            final JButton btn = new JButton(tagObj.name);
            btn.setToolTipText(tagObj.tooltip);

            ActionListener actionListener;
            if ((displayCategory != null && displayCategory.equals(tagObj.category)) || (StringUtils.isNotEmpty(searchTag) && (regex ? tagObj.name.matches(searchTag) : tagObj.name.contains(searchTag)))) {
                if (!isNativeTheme && !isDarkTheme) {
                    btn.setBackground(Color.decode("#005a70"));
                    btn.setForeground(Color.white);
                }
                btn.putClientProperty("tag", tagObj);

                actionListener = new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        String selectedText = inputArea.getSelectedText();
                        if (selectedText == null) {
                            selectedText = "";
                        }
                        String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                        String tagStart = tagStartEnd[0];
                        String tagEnd = tagStartEnd[1];
                        inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                        Highlighter.Highlight[] highlights = inputArea.getHighlighter().getHighlights();
                        if (highlights.length > 0) {
                            for (Highlighter.Highlight highlight : highlights) {
                                inputArea.select(highlight.getStartOffset(), highlight.getEndOffset());
                                selectedText = inputArea.getSelectedText();
                                if (selectedText != null) {
                                    tagStartEnd = Convertors.generateTagStartEnd(tagObj);
                                    tagStart = tagStartEnd[0];
                                    tagEnd = tagStartEnd[1];
                                    inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                                }
                            }
                        }
                        //TODO Auto convert input
//                    outputArea.setText(convert(inputArea.getText()));
//                    outputArea.selectAll();
                    }
                };

                btn.addActionListener(actionListener);
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

    public static String getContext(IRequestInfo analyzedRequest) {
        if(analyzedRequest == null) {
            return null;
        }
        if(analyzedRequest.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
            return "JSON";
        }
        if(analyzedRequest.getMethod() != null && analyzedRequest.getMethod().equalsIgnoreCase("GET")) {
            return "GET";
        }
        if(analyzedRequest.getMethod() != null && analyzedRequest.getMethod().equalsIgnoreCase("POST")) {
            return "POST";
        }
        return null;
    }

    public static ActionListener generateTagActionListener(final IContextMenuInvocation invocation, Tag tagObj) {
        return  e -> {
            String[] tagStartEnd = Convertors.generateTagStartEnd(tagObj);
            String tagStart = tagStartEnd[0];
            String tagEnd = tagStartEnd[1];
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
                int[] bounds = invocation.getSelectionBounds();
                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                if(allowTagCount) {
                    IRequestInfo analyzedRequest = helpers.analyzeRequest(message);
                    String context = getContext(analyzedRequest);
                    if(contextTagCount.containsKey(context)) {
                        int currentCount = contextTagCount.get(context).get(tagObj.name) == null ? 0 : contextTagCount.get(context).get(tagObj.name);
                        contextTagCount.get(context).put(tagObj.name, currentCount + 1);
                    }

                    int count = tagCount.get(tagObj.name) == null ? 0 : tagCount.get(tagObj.name);
                    tagCount.put(tagObj.name, count + 1);
                }
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                    outputStream.write(helpers.stringToBytes(tagStart));
                    outputStream.write(Arrays.copyOfRange(message, bounds[0], bounds[1]));
                    outputStream.write(helpers.stringToBytes(tagEnd));
                    outputStream.write(Arrays.copyOfRange(message, bounds[1], message.length));
                    outputStream.flush();
                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                } catch (IOException e1) {
                    System.err.println(e1.toString());
                }
            }
        };
    }

    public static JMenu createTagMenuForCategory(List<Tag> tags, Tag.Category category, final IContextMenuInvocation invocation, String searchTag, Boolean regex, Tag specificTag) {
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
                menu.addActionListener(generateTagActionListener(invocation, tagObj));
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

    public static void applyThemeToRSyntaxTextArea(RSyntaxTextArea area, String themeName) {
        try {
            Theme theme = Theme.load(Utils.class.getResourceAsStream(
                    "/org/fife/ui/rsyntaxtextarea/themes/"+themeName+".xml"));
            theme.apply(area);
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
    public static void fixRSyntaxAreaBurp() {
        UIManager.put("RSyntaxTextAreaUI.actionMap", null);
        UIManager.put("RSyntaxTextAreaUI.inputMap", null);
        UIManager.put("RTextAreaUI.actionMap", null);
        UIManager.put("RTextAreaUI.inputMap", null);
    }

    public static void configureRSyntaxArea(HackvertorInput area) {
        area.setLineWrap(true);
        if(BurpExtender.isDarkTheme) {
            Utils.applyThemeToRSyntaxTextArea(area, "dark");
        }
        callbacks.customizeUiComponent(area);
    }

    public static void setMarginAndPadding(JComponent comp, int amount) {
        Border margin = new EmptyBorder(amount,amount,amount,amount);
        comp.setBorder(margin);
    }

    public static String sanitizeTagName(String tagName) {
        return tagName.replaceAll(tagNameRegex, "");
    }

    public static Boolean validateParam(String param) {
        return param.matches(paramRegex);
    }

    public static Boolean validateCode(String code) {
        return !code.isEmpty() && code.length() <= MAX_TAG_CODE_LEN;
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
 }
