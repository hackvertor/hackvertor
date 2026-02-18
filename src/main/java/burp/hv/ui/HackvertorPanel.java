package burp.hv.ui;

import burp.hv.*;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.Tag;
import burp.hv.tags.TagStore;
import burp.hv.utils.GridbagUtils;
import burp.hv.utils.TagUtils;
import burp.hv.utils.Utils;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.*;

import static burp.hv.HackvertorExtension.*;
import static burp.hv.Convertors.*;
import static java.awt.GridBagConstraints.*;
import static java.awt.GridBagConstraints.BOTH;

public class HackvertorPanel extends JPanel {

    private final Hackvertor hackvertor;
    private final HackvertorInput inputArea;
    private final HackvertorInput outputArea;
    private JTabbedPane tabs;
    private final HackvertorHistory history;
    private boolean isNavigatingHistory = false;
    private String lastAddedInput = "";
    private String lastAddedOutput = "";
    private JLabel historyPositionLabel;
    
    public HackvertorPanel(Hackvertor hackvertor, boolean showLogo, boolean hideOutput, boolean isMessageEditor){
        super(new GridBagLayout());
        this.hackvertor = hackvertor;
        this.inputArea = new HackvertorInput();
        this.outputArea = new HackvertorInput();
        this.history = new HackvertorHistory(isMessageEditor);
        Utils.configureTextArea(this.inputArea);
        Utils.configureTextArea(this.outputArea);
        buildPanel(showLogo, hideOutput, isMessageEditor);
    }

    public JTabbedPane getTabs() {
        return tabs;
    }

    private void buildPanel(boolean showLogo, boolean hideOutput, boolean isMessageEditor){
        tabs = buildTabbedPane(hideOutput);
        JPanel topBar = new JPanel(new GridBagLayout());
        topBar.setPreferredSize(new Dimension(-1, 100));
        topBar.setMinimumSize(new Dimension(-1, 100));
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
        // Use a generic monospaced font for hex display/editing
        hexView.setFont(new Font(Font.MONOSPACED, Font.PLAIN, hexView.getFont().getSize()));
        hexView.setRows(0);
        hexView.setOpaque(true);
        // Allow editing so users can paste or type hex directly
        hexView.setEditable(true);
        // Enable line wrap but avoid breaking in the middle of words/bytes
        hexView.setLineWrap(true);
        hexView.setWrapStyleWord(true);
        hexView.setVisible(false);
        final JScrollPane hexScroll = new JScrollPane(hexView);
        hexScroll.setPreferredSize(new Dimension(-1, 100));
        hexScroll.setMinimumSize(new Dimension(-1, 100));
        // Split buttons into left and right sections so we can align important actions (like Smart Decode / Apply hex)
        // Use GridBagLayout so button groups can reflow vertically when horizontal space is limited.
        JPanel buttonsPanel = new JPanel(new GridBagLayout());
        JPanel leftButtons = new JPanel(new WrapLayout(FlowLayout.LEFT, 5, 5));
        // use WrapLayout for the right side too so buttons wrap into additional rows when needed
        JPanel rightButtons = new JPanel(new WrapLayout(FlowLayout.RIGHT, 5, 5));
        inputArea.setLineWrap(true);
        inputArea.setRows(0);
        final UndoManager undo = new UndoManager();
        Document doc = inputArea.getDocument();

        doc.addUndoableEditListener(evt -> undo.addEdit(evt.getEdit()));
        inputArea.getActionMap().put("Undo",
                new AbstractAction("Undo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canUndo()) {
                                undo.undo();
                            }
                        } catch (CannotUndoException ignored) {
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
                        } catch (CannotRedoException ignored) {
                        }
                    }
                });

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");
        final JScrollPane inputScroll = new JScrollPane(inputArea);
        final JLabel inputLabel = new JLabel("Input:");
        final JLabel inputLenLabel = new JLabel("0");
        final JLabel inputRealLenLabel = new JLabel("0");
        inputRealLenLabel.setOpaque(true);
        inputLenLabel.setOpaque(true);
        if(!hideOutput) {
            DocumentListener documentListener = new DocumentListener() {
                LinkedBlockingQueue queue = new LinkedBlockingQueue<>(1);
                ExecutorService executorService = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                        queue, new ThreadPoolExecutor.DiscardOldestPolicy());

                public void scheduleUpdate() {
                    if (isNavigatingHistory) {
                        return;
                    }
                    executorService.submit(() -> {
                        String output = hackvertor.convert(inputArea.getText(), null);
                        try {
                            outputArea.getDocument().remove(0, outputArea.getDocument().getLength());
                            outputArea.getDocument().insertString(0, output, null);
                        } catch (BadLocationException e) {
                            e.printStackTrace();
                        }
                        outputArea.setCaretPosition(0);
                        addToHistory();
                    });
                }


                public void changedUpdate(DocumentEvent documentEvent) {
                    updateLen();
                    scheduleUpdate();
                }

                public void insertUpdate(DocumentEvent documentEvent) {
                    updateLen();
                    scheduleUpdate();
                    if (!isNavigatingHistory) {
                        history.resetIndex();
                        updateHistoryPositionLabel();
                    }
                }

                public void removeUpdate(DocumentEvent documentEvent) {
                    updateLen();
                    scheduleUpdate();
                    if (!isNavigatingHistory) {
                        history.resetIndex();
                        updateHistoryPositionLabel();
                    }
                }

                private void updateLen() {
                    int len = inputArea.getText().length();
                    int realLen = calculateRealLen(inputArea.getText());
                    inputLenLabel.setText("" + len);
                    inputRealLenLabel.setText("" + realLen);
                }
            };
            inputArea.getDocument().addDocumentListener(documentListener);
        }
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
        outputLenLabel.setOpaque(true);
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
        swapButton.setToolTipText("Swap input and output content");
        swapButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText(outputArea.getText());
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });

        final JButton selectInputButton = new JButton("Select input");
        selectInputButton.setToolTipText("Select all text in the input area");
        selectInputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.requestFocus();
                inputArea.selectAll();
            }
        });

        final JButton selectOutputButton = new JButton("Select output");
        selectOutputButton.setToolTipText("Select all text in the output area");
        selectOutputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.requestFocus();
                outputArea.selectAll();
            }
        });

        final JButton clearTagsButton = new JButton("Clear tags");
        clearTagsButton.setToolTipText("Remove all Hackvertor tags from input");
        clearTagsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String input = inputArea.getText();
                input = Hackvertor.removeHackvertorTags(input);
                inputArea.setText(input);
                inputArea.requestFocus();
            }
        });

        final JButton clearButton = new JButton("Clear");
        clearButton.setToolTipText("Clear both input and output areas");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText("");
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });

        final JButton pasteInsideButton = new JButton("Paste inside tags");
        pasteInsideButton.setToolTipText("Paste clipboard content inside existing Hackvertor tags");
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
                        Element secondNext = i + 2 < inputElements.size() - 1 ? inputElements.get(i+2) : null;
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
                inputArea.setText(TagUtils.elementSequenceToString(inputElements));
            }
        });

        final JButton convertButton = new JButton("Convert");
        convertButton.setToolTipText("Manually convert input to output");
        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                executorService.submit(() -> {
                    outputArea.setText(hackvertor.convert(inputArea.getText(), null));
                    addToHistory();
                });

            }
        });

        final JButton decode = new JButton("Smart Decode");
        decode.setToolTipText("Decode selected text, or decode partial matches in full input if nothing selected (Ctrl+Alt+D)");
        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control alt D"), "smartDecode");
        SmartDecodeAction smartDecodeAction = new SmartDecodeAction(this.inputArea, null, hackvertor);
        inputArea.getActionMap().put("smartDecode", smartDecodeAction);

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control alt F"), "findTag");
        inputArea.getActionMap().put("findTag", new AbstractAction("findTag") {
            public void actionPerformed(ActionEvent evt) {
                ArrayList<Tag> tags = hackvertor.getTags();
                TagFinderWindow finderWindow = new TagFinderWindow(HackvertorExtension.montoyaApi, inputArea, tags);
                finderWindow.show();
            }
        });

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control alt M"), "multiEncoder");
        inputArea.getActionMap().put("multiEncoder", new AbstractAction("multiEncoder") {
            public void actionPerformed(ActionEvent evt) {
                String selectedText = inputArea.getSelectedText();
                boolean hasSelection = selectedText != null && !selectedText.isEmpty();
                if (!hasSelection) {
                    selectedText = inputArea.getText();
                }
                if (selectedText == null || selectedText.isEmpty()) {
                    return;
                }
                ArrayList<Tag> tags = hackvertor.getTags();
                String textToEncode = selectedText;
                boolean replaceSelection = hasSelection;
                MultiEncoderWindow encoderWindow = new MultiEncoderWindow(
                    HackvertorExtension.montoyaApi,
                    textToEncode,
                    tags,
                    result -> {
                        if (replaceSelection) {
                            inputArea.replaceSelection(result);
                        } else {
                            inputArea.setText(result);
                        }
                    }
                );
                encoderWindow.show();
            }
        });

        decode.addActionListener(smartDecodeAction);
        JButton rehydrateTagExecutionKey = new JButton("Rehydrate Tags");
        rehydrateTagExecutionKey.setToolTipText("Replace tag execution keys in selected text with your current key");
        rehydrateTagExecutionKey.setEnabled(false);
        this.inputArea.addCaretListener(new CaretListener() {
            @Override
            public void caretUpdate(CaretEvent e) {
                boolean hasSelection = inputArea.getSelectionStart() != inputArea.getSelectionEnd();
                rehydrateTagExecutionKey.setEnabled(hasSelection);
            }
        });
        rehydrateTagExecutionKey.addActionListener((x) -> {
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure? This will replace any tag execution key with your current one. You should not run this on untrusted code");
            if(confirm == 0) {
                String existingText = this.inputArea.getSelectedText();
                this.inputArea.replaceSelection(existingText.replaceAll("[a-f0-9]{32}", tagCodeExecutionKey));
            }
        });

        final JButton firstButton = new JButton("↞");
        firstButton.setEnabled(!hideOutput);
        firstButton.setToolTipText("First history entry");
        firstButton.setPreferredSize(new Dimension(50, firstButton.getPreferredSize().height));
        firstButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                navigateToFirst();
            }
        });

        final JButton previousButton = new JButton("←");
        previousButton.setEnabled(!hideOutput);
        previousButton.setToolTipText("Previous history");
        previousButton.setPreferredSize(new Dimension(50, previousButton.getPreferredSize().height));
        previousButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                navigateHistory(true);
            }
        });

        historyPositionLabel = new JLabel("0/0");
        historyPositionLabel.setEnabled(!hideOutput);
        historyPositionLabel.setHorizontalAlignment(SwingConstants.CENTER);
        historyPositionLabel.setToolTipText("History position");
        updateHistoryPositionLabel();

        final JButton nextButton = new JButton("→");
        nextButton.setToolTipText("Next history");
        nextButton.setEnabled(!hideOutput);
        nextButton.setPreferredSize(new Dimension(50, nextButton.getPreferredSize().height));
        nextButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                navigateHistory(false);
            }
        });

        final JButton lastButton = new JButton("↠");
        lastButton.setEnabled(!hideOutput);
        lastButton.setToolTipText("Last history entry");
        lastButton.setPreferredSize(new Dimension(50, lastButton.getPreferredSize().height));
        lastButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                navigateToLast();
            }
        });

        final JButton clearHistoryButton = new JButton("Clear history");
        clearHistoryButton.setToolTipText("Clear all Hackvertor history");
        clearHistoryButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(
                    HackvertorPanel.this,
                    "Are you sure you want to clear all Hackvertor history?",
                    "Clear History",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE
                );
                if (result == JOptionPane.YES_OPTION) {
                    history.clear();
                    lastAddedInput = "";
                    lastAddedOutput = "";
                    updateHistoryPositionLabel();
                    JOptionPane.showMessageDialog(
                        HackvertorPanel.this,
                        "Hackvertor history has been cleared.",
                        "History Cleared",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                }
            }
        });

        final JButton applyHex = new JButton("Apply hex");
        applyHex.setToolTipText("Replace selected text with the hex value from the hex field");
        applyHex.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String hexText = hexView.getText();
                if (hexText == null || hexText.trim().isEmpty()) return;
                // convert hex (which may contain spaces/comma/dashes) to ascii (local implementation to avoid visibility issues)
                StringBuilder sb = new StringBuilder();
                java.util.regex.Pattern p = java.util.regex.Pattern.compile("([0-9a-fA-F]{2})[\\s,\\-]?");
                java.util.regex.Matcher m = p.matcher(hexText);
                while (m.find()) {
                    m.appendReplacement(sb, "");
                    sb.append((char) Integer.parseInt(m.group(1), 16));
                }
                String replaced = sb.toString();
                // prefer replacing selection in inputArea, then outputArea, otherwise insert into inputArea
                try {
                    if (inputArea.getSelectionStart() != inputArea.getSelectionEnd()) {
                        inputArea.replaceSelection(replaced);
                        inputArea.requestFocus();
                    } else if (outputArea.getSelectionStart() != outputArea.getSelectionEnd()) {
                        outputArea.replaceSelection(replaced);
                        outputArea.requestFocus();
                    } else {
                        inputArea.replaceSelection(replaced);
                        inputArea.requestFocus();
                    }
                } catch (Exception ex) {
                    stderr.println("Error applying hex: " + ex.getMessage());
                }
            }
        });

        leftButtons.add(clearButton);
        leftButtons.add(firstButton);
        leftButtons.add(previousButton);
        leftButtons.add(historyPositionLabel);
        leftButtons.add(nextButton);
        leftButtons.add(lastButton);
        leftButtons.add(clearHistoryButton);
        leftButtons.add(clearTagsButton);
        leftButtons.add(rehydrateTagExecutionKey);
        if(!hideOutput) {
            leftButtons.add(swapButton);
        }
        leftButtons.add(selectInputButton);
        if (!hideOutput) {
            leftButtons.add(selectOutputButton);
            leftButtons.add(pasteInsideButton);
        }
        leftButtons.add(decode);

        // Move the Convert button to the right panel (keep Smart Decode on the left)
        rightButtons.add(convertButton);
        rightButtons.add(applyHex);

    // place left and right groups into buttonsPanel using GridBag so they can wrap and grow vertically
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridx = 0;
    gbc.gridy = 0;
    gbc.weightx = 1.0;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.anchor = GridBagConstraints.WEST;
    buttonsPanel.add(leftButtons, gbc);

    gbc = new GridBagConstraints();
    gbc.gridx = 1;
    gbc.gridy = 0;
    gbc.weightx = 0.0;
    gbc.fill = GridBagConstraints.NONE;
    gbc.anchor = GridBagConstraints.EAST;
    buttonsPanel.add(rightButtons, gbc);
        GridBagConstraints c = GridbagUtils.createConstraints(1, 0, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = FIRST_LINE_END;
        c.ipadx = 20;
        c.ipady = 20;
        topBar.add(logoLabel, c);
        c = GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        c.weighty = 1;
        topBar.add(tabs, c);
        c = GridbagUtils.createConstraints(0, 0, 2, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        this.add(topBar, c);
        JPanel inputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = GridbagUtils.createConstraints(0, 0, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLabel, c);
        c = GridbagUtils.createConstraints(1, 1, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLenLabel, c);
        c = GridbagUtils.createConstraints(2, 1, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputRealLenLabel, c);
        if(!hideOutput) {
            this.add(inputLabelsPanel, GridbagUtils.createConstraints(0, 2, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER));
        }
        c = GridbagUtils.createConstraints(0, 3, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        this.add(inputScroll, c);
        JPanel outputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = GridbagUtils.createConstraints(0, 1, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputLabel, c);
        c = GridbagUtils.createConstraints(1, 1, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputLenLabel, c);
        c = GridbagUtils.createConstraints(2, 1, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        outputLabelsPanel.add(outputRealLenLabel, c);
        if(!hideOutput) {
            this.add(outputLabelsPanel, GridbagUtils.createConstraints(1, 2, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER));
        }
        c = GridbagUtils.createConstraints(1, 3, 1, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        if(!hideOutput) {
            this.add(outputScroll, c);
        }
        c = GridbagUtils.createConstraints(0, 4, 2, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.anchor = GridBagConstraints.SOUTH;
        c.fill = BOTH;
        c.weightx = 1.0;
        this.add(buttonsPanel, c);
        SearchPanel searchPanel = new SearchPanel(hackvertor, this);
        searchPanel.setPreferredSize(new Dimension(-1, 80));
        searchPanel.setMinimumSize(new Dimension(-1, 80));
        this.add(searchPanel, GridbagUtils.createConstraints(0, 5, 2, BOTH, 1, 0, 0, 0, LAST_LINE_START));
        c = GridbagUtils.createConstraints(0, 6, 2, GridBagConstraints.NONE, 0, 0, 0, 0, CENTER);
        c.insets = new Insets(5, 5, 5, 5);
        c.anchor = LAST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        // Always show the hex view so users can edit/paste hex even when the output panel is hidden
        this.add(hexScroll, c);
    }

    public JTabbedPane buildTabbedPane(boolean shouldSelectInput){
        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        ArrayList<String> categories = new ArrayList<>();
        for (Tag.Category category : Tag.Category.values()) {
            categories.add(category.name());
        }
        boolean sortTagCategories;
        try {
            sortTagCategories = generalSettings.getBoolean("sortTagCategories");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            callbacks.printError("Error loading settings:"+e);
            throw new RuntimeException(e);
        }
        if(sortTagCategories) {
            Collections.sort(categories);
        }
        for (String category : categories) {
            tabs.addTab(category, TagUtils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.valueOf(category), null, false));
        }

        JPanel tagStoreContainer = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton tagStoreButton = new JButton("Open tag Store");
        tagStoreButton.setPreferredSize(new Dimension(120, 25));
        tagStoreButton.addActionListener((e) -> {
            TagStore.showTagStore();
        });
        tagStoreContainer.add(tagStoreButton);
        tabs.addTab("Tag store", tagStoreContainer);

        tabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int tabIndex = tabs.getSelectedIndex();
                if (tabs.getTitleAt(tabIndex).equals("Custom")) {
                    tabs.setComponentAt(tabIndex, TagUtils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.Custom, null, false));
                } else if(tabs.getTitleAt(tabIndex).equals("Globals")) {
                    tabs.setComponentAt(tabIndex, TagUtils.createButtons(hackvertor.getTags(), inputArea, Tag.Category.Globals, null, false));

                }
            }
        });
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
                if (data.contains("</@")) {
                    code = data;
                } else {
                    code = "<@auto_decode_no_decrypt>" + data + "</@auto_decode_no_decrypt>";
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

    private void navigateHistory(boolean isPrevious) {
        HackvertorHistory.HistoryEntry entry = isPrevious ? history.getPrevious() : history.getNext();
        if (entry != null) {
            isNavigatingHistory = true;
            inputArea.setText(entry.getInput());
            outputArea.setText(entry.getOutput());
            updateHistoryPositionLabel();
            SwingUtilities.invokeLater(() -> {
                isNavigatingHistory = false;
            });
        }
    }

    private void navigateToFirst() {
        HackvertorHistory.HistoryEntry entry = history.getFirst();
        if (entry != null) {
            isNavigatingHistory = true;
            inputArea.setText(entry.getInput());
            outputArea.setText(entry.getOutput());
            updateHistoryPositionLabel();
            SwingUtilities.invokeLater(() -> {
                isNavigatingHistory = false;
            });
        }
    }

    private void navigateToLast() {
        HackvertorHistory.HistoryEntry entry = history.getLast();
        if (entry != null) {
            isNavigatingHistory = true;
            inputArea.setText(entry.getInput());
            outputArea.setText(entry.getOutput());
            updateHistoryPositionLabel();
            SwingUtilities.invokeLater(() -> {
                isNavigatingHistory = false;
            });
        }
    }

    private void addToHistory() {
        if (isNavigatingHistory) {
            return;
        }

        String input = inputArea.getText();
        String output = outputArea.getText();

        // Only add to history if both input exists and either input or output has changed
        if (!input.isEmpty() && (!input.equals(lastAddedInput) || !output.equals(lastAddedOutput))) {
            history.addEntry(input, output);
            lastAddedInput = input;
            lastAddedOutput = output;
            updateHistoryPositionLabel();
        }
    }

    private void updateHistoryPositionLabel() {
        if (historyPositionLabel != null) {
            int size = history.size();
            if (size == 0) {
                historyPositionLabel.setText("0/0");
            } else {
                int currentIndex = history.getCurrentIndex();
                // Display as 1-based index for user friendliness
                historyPositionLabel.setText((currentIndex + 1) + "/" + size);
            }
        }
    }

    public void refreshHistory() {
        if (history != null) {
            history.reloadFromPersistence();
            updateHistoryPositionLabel();
        }
    }
}
