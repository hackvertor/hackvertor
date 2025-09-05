package burp.hv.ui;

import burp.hv.Hackvertor;
import burp.hv.utils.TagUtils;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static burp.hv.HackvertorExtension.isDarkTheme;
import static burp.hv.HackvertorExtension.stderr;

public class SearchPanel extends JPanel {

    private final Hackvertor hackvertor;
    private final HackvertorPanel hackvertorPanel;

    public SearchPanel(Hackvertor hackvertor, HackvertorPanel hackvertorPanel){
        super(new FlowLayout(FlowLayout.LEFT));
        this.hackvertor = hackvertor;
        this.hackvertorPanel = hackvertorPanel;

        this.setPreferredSize(new Dimension(1500, 80));
        String[] searchOptionsText = {"Search tags", "Search Input", "Search output", "Find & Replace Input", "Find & Replace Output"};
        JComboBox searchOptions = new JComboBox(searchOptionsText);
        JTextField searchBox = new JTextField();
        JTextField replaceBox = new JTextField();
        JButton replaceButton = new JButton("Replace");
        JButton replaceAllButton = new JButton("Replace All");
        JCheckBox regexCheckbox = new JCheckBox("Regex?");
        searchBox.setPreferredSize(new Dimension(300, 30));
        replaceBox.setPreferredSize(new Dimension(300, 30));
        JPanel tagsPanel = new JPanel();
        tagsPanel.setAutoscrolls(false);
        tagsPanel.setPreferredSize(new Dimension(1500, 50));
        
        // Initially hide replace components
        replaceBox.setVisible(false);
        replaceButton.setVisible(false);
        replaceAllButton.setVisible(false);
        
        searchBox.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {

                try {
                    Pattern.compile(searchBox.getText());
                } catch (PatternSyntaxException ex) {
                    stderr.println(ex);
                    return;
                }

                if (searchOptions.getSelectedIndex() == 0) {
                    searchTags(searchBox.getText(), tagsPanel, regexCheckbox.isSelected());
                } else if (searchOptions.getSelectedIndex() == 1 || searchOptions.getSelectedIndex() == 3) {
                    search(searchBox.getText(), hackvertorPanel.getInputArea(), regexCheckbox.isSelected());
                } else if (searchOptions.getSelectedIndex() == 2 || searchOptions.getSelectedIndex() == 4) {
                    search(searchBox.getText(), hackvertorPanel.getOutputArea(), regexCheckbox.isSelected());
                }
            }
        });
        
        searchOptions.addActionListener(e -> {
            int selectedIndex = searchOptions.getSelectedIndex();
            boolean isReplace = selectedIndex >= 3;
            replaceBox.setVisible(isReplace);
            replaceButton.setVisible(isReplace);
            replaceAllButton.setVisible(isReplace);
            tagsPanel.setVisible(!isReplace);
            
            // Trigger search when switching modes
            if (searchBox.getText().length() > 0) {
                searchBox.getKeyListeners()[0].keyReleased(null);
            }
        });
        
        replaceButton.addActionListener(e -> {
            if (searchOptions.getSelectedIndex() == 3) {
                replace(searchBox.getText(), replaceBox.getText(), hackvertorPanel.getInputArea(), regexCheckbox.isSelected(), false);
            } else if (searchOptions.getSelectedIndex() == 4) {
                replace(searchBox.getText(), replaceBox.getText(), hackvertorPanel.getOutputArea(), regexCheckbox.isSelected(), false);
            }
        });
        
        replaceAllButton.addActionListener(e -> {
            if (searchOptions.getSelectedIndex() == 3) {
                replace(searchBox.getText(), replaceBox.getText(), hackvertorPanel.getInputArea(), regexCheckbox.isSelected(), true);
            } else if (searchOptions.getSelectedIndex() == 4) {
                replace(searchBox.getText(), replaceBox.getText(), hackvertorPanel.getOutputArea(), regexCheckbox.isSelected(), true);
            }
        });
        
        this.add(searchOptions);
        this.add(searchBox);
        this.add(replaceBox);
        this.add(replaceButton);
        this.add(replaceAllButton);
        this.add(regexCheckbox);
        this.add(tagsPanel);
    }

    void searchTags(String input, JPanel tagsPanel, Boolean regex) {
        tagsPanel.removeAll();
        JScrollPane tags = TagUtils.createButtons(hackvertor.getTags(), hackvertorPanel.getInputArea(), null, input, regex);
        tags.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        tags.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        tags.setPreferredSize(new Dimension(1500, 40));
        tags.setBorder(null);
        tags.setAutoscrolls(false);
        tagsPanel.add(tags);
        tagsPanel.repaint();
        tagsPanel.validate();
    }

    void search(String findText, JTextArea element, Boolean regex) {
        try {
            Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(isDarkTheme ? Color.gray : Color.yellow);
            element.getHighlighter().removeAllHighlights();
            if (findText.length() == 0) {
                return;
            }
            int findLength = findText.length();
            Document doc = element.getDocument();
            String text = doc.getText(0, doc.getLength());
            int count = 0;
            int offset = 0;
            Pattern pattern = null;
            Matcher matcher = null;
            Boolean matched = false;
            if (regex) {
                pattern = Pattern.compile(findText);
                matcher = pattern.matcher(text);
            }
            while ((offset = regex ? (matcher.find() ? matcher.start() : -1) : text.indexOf(findText, offset)) != -1) {
                if (regex) {
                    findLength = matcher.group().length();
                }
                element.select(offset, offset + findLength);
                element.getHighlighter().addHighlight(offset, offset + findLength, painter);
                offset += findLength;
                matched = true;
                count++;
            }
            if (!matched) {
                element.select(0, 0);
            }
        } catch (BadLocationException e) {
        }
    }
    
    void replace(String findText, String replaceText, JTextArea element, Boolean regex, Boolean replaceAll) {
        try {
            if (findText.length() == 0) {
                return;
            }
            
            Document doc = element.getDocument();
            String text = doc.getText(0, doc.getLength());
            String newText = text;
            
            if (replaceAll) {
                if (regex) {
                    Pattern pattern = Pattern.compile(findText);
                    newText = pattern.matcher(text).replaceAll(replaceText);
                } else {
                    newText = text.replace(findText, replaceText);
                }
                element.setText(newText);
            } else {
                // Replace only the currently selected text if it matches
                int selectionStart = element.getSelectionStart();
                int selectionEnd = element.getSelectionEnd();
                
                if (selectionStart != selectionEnd) {
                    String selectedText = element.getSelectedText();
                    boolean shouldReplace = false;
                    
                    if (regex) {
                        Pattern pattern = Pattern.compile(findText);
                        shouldReplace = pattern.matcher(selectedText).matches();
                    } else {
                        shouldReplace = selectedText.equals(findText);
                    }
                    
                    if (shouldReplace) {
                        if (regex) {
                            Pattern pattern = Pattern.compile(findText);
                            String replacement = pattern.matcher(selectedText).replaceFirst(replaceText);
                            element.replaceSelection(replacement);
                        } else {
                            element.replaceSelection(replaceText);
                        }
                    }
                }
                
                // Search for next occurrence
                search(findText, element, regex);
            }
        } catch (BadLocationException e) {
        } catch (PatternSyntaxException e) {
            stderr.println(e);
        }
    }
}
