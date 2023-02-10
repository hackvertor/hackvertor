package burp.ui;

import burp.*;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.apache.commons.lang3.StringUtils;
import org.fife.ui.autocomplete.*;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.stream.Collectors;

import static burp.BurpExtender.*;
import static burp.Convertors.*;
import static java.awt.GridBagConstraints.*;
import static java.awt.GridBagConstraints.BOTH;

public class HackvertorPanel extends JPanel {
    
    private final Hackvertor hackvertor;
    private final HackvertorInput inputArea;
    private final HackvertorInput outputArea;
    private JTabbedPane tabs;
    
    public HackvertorPanel(Hackvertor hackvertor, boolean showLogo){
        super(new GridBagLayout());
        this.hackvertor = hackvertor;
        JTextComponent.removeKeymap("RTextAreaKeymap");
        this.inputArea = new HackvertorInput();
        this.outputArea = new HackvertorInput();
        Utils.fixRSyntaxAreaBurp();
        callbacks.customizeUiComponent(this.inputArea);
        callbacks.customizeUiComponent(this.outputArea);
        this.inputArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
        this.outputArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
        Utils.configureRSyntaxArea(this.inputArea);
        Utils.configureRSyntaxArea(this.outputArea);
        this.inputArea.setCodeFoldingEnabled(true);
        this.generateAutoCompletion(this.inputArea);
        buildPanel(showLogo);
    }

    public JTabbedPane getTabs() {
        return tabs;
    }

    private void generateAutoCompletion(RSyntaxTextArea input) {
        DefaultCompletionProvider provider = new DefaultCompletionProvider();
        provider.setAutoActivationRules(false, "<");
        ArrayList<Tag> tags = hackvertor.getTags();
        for(Tag tag : tags) {
            BasicCompletion acTag = new BasicCompletion(provider, tag.name);
            provider.addCompletion(acTag);
        }
        JSONArray customTags = hackvertor.getCustomTags();
        for (int i = 0; i < customTags.length(); i++) {
            JSONObject customTag = (JSONObject) hackvertor.getCustomTags().get(i);
            String tagName = customTag.getString("tagName");
            BasicCompletion acTag = new BasicCompletion(provider, tagName);
            provider.addCompletion(acTag);
        }
        HackvertorTagCompletion ac = new HackvertorTagCompletion(provider);
        ac.setAutoActivationDelay(250);
        ac.setAutoActivationEnabled(true);
        ac.install(input);
    }

    private void buildPanel(boolean showLogo){
        tabs = buildTabbedPane();
        JPanel topBar = new JPanel(new GridBagLayout());
        topBar.setPreferredSize(new Dimension(-1, 110));
        topBar.setMinimumSize(new Dimension(-1, 110));
        JLabel logoLabel;
        if (isDarkTheme) {
            logoLabel = new JLabel(createImageIcon("/images/logo-dark.png", "logo"));
        } else {
            logoLabel = new JLabel(createImageIcon("/images/logo-light.png", "logo"));
        }
        if (!showLogo) {
            logoLabel = new JLabel();
        }
        final JTextArea hexView = new JTextArea();
        hexView.setFont(new Font("Courier New", Font.PLAIN, hexView.getFont().getSize()));
        hexView.setRows(0);
        hexView.setOpaque(true);
        hexView.setEditable(false);
        hexView.setLineWrap(true);
        if (!isDarkTheme) {
            hexView.setBackground(Color.decode("#FFF5BF"));
            hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        }
        hexView.setVisible(false);
        final JScrollPane hexScroll = new JScrollPane(hexView);
        hexScroll.setPreferredSize(new Dimension(-1, 100));
        hexScroll.setMinimumSize(new Dimension(-1, 100));
        JPanel buttonsPanel = new JPanel(new GridLayout(1, 0, 10, 0));
        inputArea.setLineWrap(true);
        inputArea.setRows(0);
        final UndoManager undo = new UndoManager();
        Document doc = inputArea.getDocument();

        doc.addUndoableEditListener(new UndoableEditListener() {
            public void undoableEditHappened(UndoableEditEvent evt) {
                undo.addEdit(evt.getEdit());
            }
        });
        inputArea.getActionMap().put("Undo",
                new AbstractAction("Undo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canUndo()) {
                                undo.undo();
                            }
                        } catch (CannotUndoException e) {
                        }
                    }
                });
        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
        inputArea.getActionMap().put("Redo",
                new AbstractAction("Redo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canRedo()) {
                                undo.redo();
                            }
                        } catch (CannotRedoException e) {
                        }
                    }
                });

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");
        final JScrollPane inputScroll = new JScrollPane(inputArea);
        final JLabel inputLabel = new JLabel("Input:");
        final JLabel inputLenLabel = new JLabel("0");
        final JLabel inputRealLenLabel = new JLabel("0");
        inputRealLenLabel.setOpaque(true);
        if (!isDarkTheme) {
            inputRealLenLabel.setForeground(Color.decode("#ffffff"));
            inputRealLenLabel.setBackground(Color.decode("#ff0027"));
            inputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        } else {
            inputRealLenLabel.setForeground(Color.decode("#000000"));
            inputRealLenLabel.setBackground(Color.decode("#b6b6b6"));
            inputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        }
        inputLenLabel.setOpaque(true);
        if (!isDarkTheme) {
            inputLenLabel.setBackground(Color.decode("#FFF5BF"));
            inputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        }
        DocumentListener documentListener = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText(), null));
                outputArea.setCaretPosition(0);
            }

            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText(), null));
                outputArea.setCaretPosition(0);
            }

            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hackvertor.convert(inputArea.getText(), null));
                outputArea.setCaretPosition(0);
            }

            private void updateLen(DocumentEvent documentEvent) {
                int len = inputArea.getText().length();
                int realLen = calculateRealLen(inputArea.getText());
                inputLenLabel.setText("" + len);
                inputRealLenLabel.setText("" + realLen);
            }
        };
        inputArea.getDocument().addDocumentListener(documentListener);
        inputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        inputArea.transferFocusBackward();
                    } else {
                        inputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });
        inputArea.addCaretListener(new CaretListener() {
            public void caretUpdate(CaretEvent e) {
                String selectedText = inputArea.getSelectedText();
                if (selectedText != null) {
                    hexView.setVisible(true);
                    String output = ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });
        outputArea.setRows(0);
        outputArea.setLineWrap(true);
        outputArea.addCaretListener(new CaretListener() {
            public void caretUpdate(CaretEvent e) {
                String selectedText = outputArea.getSelectedText();
                if (selectedText != null) {
                    hexView.setVisible(true);
                    String output = ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });
        final JScrollPane outputScroll = new JScrollPane(outputArea);
        final JLabel outputLabel = new JLabel("Output:");
        final JLabel outputLenLabel = new JLabel("0");
        final JLabel outputRealLenLabel = new JLabel("0");
        outputRealLenLabel.setOpaque(true);
        if (!isDarkTheme) {
            outputRealLenLabel.setForeground(Color.decode("#ffffff"));
            outputRealLenLabel.setBackground(Color.decode("#ff0027"));
            outputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        } else {
            outputRealLenLabel.setForeground(Color.decode("#000000"));
            outputRealLenLabel.setBackground(Color.decode("#b6b6b6"));
            outputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        }
        outputLenLabel.setOpaque(true);
        if (!isDarkTheme) {
            outputLenLabel.setBackground(Color.decode("#FFF5BF"));
            outputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        }
        DocumentListener documentListener2 = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }

            private void updateLen(DocumentEvent documentEvent) {
                int len = outputArea.getText().length();
                int realLen = calculateRealLen(outputArea.getText());
                outputLenLabel.setText("" + len);
                outputRealLenLabel.setText("" + realLen);
            }
        };
        outputArea.getDocument().addDocumentListener(documentListener2);
        outputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        outputArea.transferFocusBackward();
                    } else {
                        outputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });
        final JButton swapButton = new JButton("Swap");
        if (!isNativeTheme && !isDarkTheme) {
            swapButton.setBackground(Color.black);
            swapButton.setForeground(Color.white);
        }
        swapButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText(outputArea.getText());
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });

        final JButton selectInputButton = new JButton("Select input");
        selectInputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.requestFocus();
                inputArea.selectAll();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            selectInputButton.setForeground(Color.white);
            selectInputButton.setBackground(Color.black);
        }

        final JButton selectOutputButton = new JButton("Select output");
        selectOutputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.requestFocus();
                outputArea.selectAll();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            selectOutputButton.setForeground(Color.white);
            selectOutputButton.setBackground(Color.black);
        }

        final JButton clearTagsButton = new JButton("Clear tags");
        clearTagsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String input = inputArea.getText();
                input = Hackvertor.removeHackvertorTags(input);
                inputArea.setText(input);
                inputArea.requestFocus();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            clearTagsButton.setForeground(Color.white);
            clearTagsButton.setBackground(Color.black);
        }

        final JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText("");
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            clearButton.setForeground(Color.white);
            clearButton.setBackground(Color.black);
        }

        final JButton pasteInsideButton = new JButton("Paste inside tags");
        pasteInsideButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText("");
                String input = inputArea.getText();
                String clipboard = "";
                try {
                    clipboard = Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor).toString();
                } catch (UnsupportedFlavorException | IOException unsupportedFlavorException) {
                    unsupportedFlavorException.printStackTrace();
                }

                if(StringUtils.isEmpty(clipboard)) return;

                LinkedList<Element> inputElements;
                try {
                    //TODO Cleanup
                    inputElements = HackvertorParser.parse(input);
                    for (int i = 0; i < inputElements.size(); i++) {
                        Element curr = inputElements.get(i);
                        Element next = i != inputElements.size() - 1 ? inputElements.get(i+1) : null;
                        Element secondNext = i != inputElements.size() - 2 ? inputElements.get(i+2) : null;
                        if(curr instanceof Element.StartTag){
                            if(next instanceof Element.EndTag
                                && ((Element.StartTag) curr).getIdentifier()
                                    .equalsIgnoreCase(((Element.EndTag) next).getIdentifier())) {
                                inputElements.add(i + 1, new Element.TextElement(clipboard));
                            }else if(next instanceof Element.TextElement && secondNext instanceof Element.EndTag){
                                if(((Element.StartTag) curr).getIdentifier()
                                        .equalsIgnoreCase(((Element.EndTag) secondNext).getIdentifier())){
                                    ((Element.TextElement) next).setContent(clipboard);
                                }
                            }
                        }
                    }
                }catch (ParseException ex){
                    //TODO Better error handling.
                    ex.printStackTrace();
                    return;
                }
                inputArea.setText(Utils.elementSequenceToString(inputElements));
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            pasteInsideButton.setForeground(Color.white);
            pasteInsideButton.setBackground(Color.black);
        }

        final JButton convertButton = new JButton("Convert");
        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText(hackvertor.convert(inputArea.getText(), null));
            }
        });
        if (!isNativeTheme && !isDarkTheme) {
            convertButton.setBackground(Color.decode("#005a70"));
            convertButton.setForeground(Color.white);
        }
        buttonsPanel.add(clearButton);
        buttonsPanel.add(clearTagsButton);
        buttonsPanel.add(swapButton);
        buttonsPanel.add(selectInputButton);
        buttonsPanel.add(selectOutputButton);
        buttonsPanel.add(pasteInsideButton);
        buttonsPanel.add(convertButton);
        GridBagConstraints c = createConstraints(1, 0, 1);
        c.anchor = FIRST_LINE_END;
        c.ipadx = 20;
        c.ipady = 20;
        topBar.add(logoLabel, c);
        c = createConstraints(0, 0, 1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        c.weighty = 1;
        topBar.add(tabs, c);
        c = createConstraints(0, 0, 2);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        this.add(topBar, c);
        JPanel inputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0, 0, 1);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLabel, c);
        c = createConstraints(1, 1, 1);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLenLabel, c);
        c = createConstraints(2, 1, 1);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputRealLenLabel, c);
        this.add(inputLabelsPanel, createConstraints(0, 2, 1));
        c = createConstraints(0, 3, 1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        this.add(inputScroll, c);
        JPanel outputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0, 1, 1);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputLabel, c);
        c = createConstraints(1, 1, 1);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputLenLabel, c);
        c = createConstraints(2, 1, 1);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputRealLenLabel, c);
        this.add(outputLabelsPanel, createConstraints(1, 2, 1));
        c = createConstraints(1, 3, 1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        this.add(outputScroll, c);
        c = createConstraints(0, 4, 2);
        c.anchor = GridBagConstraints.SOUTH;
        c.fill = BOTH;
        c.weightx = 1.0;
        this.add(buttonsPanel, c);
        c = createConstraints(0, 5, 2);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = LAST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        this.add(hexScroll, c);
    }

    public JTabbedPane buildTabbedPane(){
        JTabbedPane tabs = new JTabbedPane();

        for (int i = 0; i < Tag.Category.values().length; i++) {
            tabs.addTab(Tag.Category.values()[i].name(), Utils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.values()[i], null, false));
        }

        tabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int tabIndex = tabs.getSelectedIndex();
                if (tabs.getTitleAt(tabIndex).equals("Custom")) {
                    tabs.setComponentAt(tabIndex, Utils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.Custom, null, false));
                }
            }
        });

        tabs.addTab("Search", new SearchPanel(hackvertor, this));

        tabs.setAutoscrolls(true);
        tabs.setSelectedIndex(tabs.indexOfTab("Encode"));

        return tabs;
    }

    public void readClipboardAndDecode() {
        try {
            String data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
            if(data.length() > 10000) {
                return;
            }
            String inputValue = inputArea.getText();
            if (inputValue.length() == 0 && !data.contains(tagCodeExecutionKey)) {
                String code;
                if (data.contains("<@/")) {
                    code = data;
                } else {
                    code = "<@auto_decode_no_decrypt>" + data + "<@/auto_decode_no_decrypt>";
                }
                String converted = Convertors.weakConvert(new HashMap<>(), hackvertor.getCustomTags(), code, null);
                if (!data.equals(converted)) {
                    inputArea.setText(code);
                }
            }
        } catch (UnsupportedFlavorException e) {
            stderr.println("Error reading data:" + e);
        } catch (IOException e) {
            stderr.println("IO exception, error reading data:" + e);
        }
    }

    public HackvertorInput getInputArea() {
        return inputArea;
    }

    public HackvertorInput getOutputArea() {
        return outputArea;
    }
}
