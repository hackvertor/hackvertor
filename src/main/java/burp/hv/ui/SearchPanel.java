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
        String[] searchOptionsText = {"Search tags", "Search Input", "Search output"};
        JComboBox searchOptions = new JComboBox(searchOptionsText);
        JTextField searchBox = new JTextField();
        JCheckBox regexCheckbox = new JCheckBox("Regex?");
        searchBox.setPreferredSize(new Dimension(300, 30));
        JPanel tagsPanel = new JPanel();
        tagsPanel.setAutoscrolls(false);
        tagsPanel.setPreferredSize(new Dimension(1500, 50));
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
                } else if (searchOptions.getSelectedIndex() == 1) {
                    search(searchBox.getText(), hackvertorPanel.getInputArea(), regexCheckbox.isSelected());
                } else if (searchOptions.getSelectedIndex() == 2) {
                    search(searchBox.getText(), hackvertorPanel.getOutputArea(), regexCheckbox.isSelected());
                }
            }
        });
        this.add(searchOptions);
        this.add(searchBox);
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
}
