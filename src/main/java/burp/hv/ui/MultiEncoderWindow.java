package burp.hv.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.Range;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.hv.Convertors;
import burp.hv.HackvertorExtension;
import burp.hv.tags.Tag;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static burp.hv.HackvertorExtension.montoyaApi;

public class MultiEncoderWindow {
    private static final int DEFAULT_WIDTH = 900;
    private static final int DEFAULT_HEIGHT = 600;
    private static final int CORNER_RADIUS = 20;
    private static final int COLUMN_COUNT = 3;

    private final MontoyaApi montoyaApi;
    private final String selectedText;
    private final ArrayList<Tag> tags;
    private final Map<String, JCheckBox> tagCheckboxes;
    private final MessageEditorHttpRequestResponse messageEditor;
    private final HttpRequestResponse baseRequestResponse;
    private JTextArea previewArea;
    private JWindow window;
    private ArrayList<Tag> selectedTags;
    private JComboBox<String> modeComboBox;

    public MultiEncoderWindow(MontoyaApi montoyaApi, String selectedText, ArrayList<Tag> tags,
                              MessageEditorHttpRequestResponse messageEditor, HttpRequestResponse baseRequestResponse) {
        this.montoyaApi = montoyaApi;
        this.selectedText = selectedText;
        this.tags = tags;
        this.tagCheckboxes = new HashMap<>();
        this.selectedTags = new ArrayList<>();
        this.messageEditor = messageEditor;
        this.baseRequestResponse = baseRequestResponse;
    }

    public void show() {
        SwingUtilities.invokeLater(() -> {
            // Create window
            window = new JWindow(montoyaApi.userInterface().swingUtils().suiteFrame());
            window.setLayout(new BorderLayout());
            window.setSize(DEFAULT_WIDTH, DEFAULT_HEIGHT);

            // Apply rounded corners
            Runnable applyRoundedCorners = () -> {
                try {
                    window.setBackground(new Color(0, 0, 0, 0));
                    SwingUtilities.invokeLater(() -> {
                        Shape shape = new RoundRectangle2D.Float(0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT,
                                                                 CORNER_RADIUS, CORNER_RADIUS);
                        window.setShape(shape);
                    });
                } catch (UnsupportedOperationException ignored) {}
            };

            // Main panel with title
            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.setBorder(new EmptyBorder(14, 14, 14, 14));
            montoyaApi.userInterface().applyThemeToComponent(mainPanel);

            // Add title panel
            JPanel titlePanel = new JPanel(new BorderLayout());
            JLabel titleLabel = new JLabel("Multi Encoder");
            titleLabel.setFont(new Font("Inter", Font.BOLD, 16));
            titlePanel.add(titleLabel, BorderLayout.WEST);
            titlePanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
            montoyaApi.userInterface().applyThemeToComponent(titlePanel);
            montoyaApi.userInterface().applyThemeToComponent(titleLabel);

            // Create search and tags panel
            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));
            montoyaApi.userInterface().applyThemeToComponent(topPanel);

            // Search field
            JTextField searchField = new JTextField();
            searchField.setFont(new Font("Monospaced", Font.PLAIN, 14));
            searchField.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
            montoyaApi.userInterface().applyThemeToComponent(searchField);

            JLabel searchLabel = new JLabel("Search tags: ");
            searchLabel.setFont(new Font("Inter", Font.PLAIN, 13));
            montoyaApi.userInterface().applyThemeToComponent(searchLabel);

            JPanel searchPanel = new JPanel(new BorderLayout());
            searchPanel.add(searchLabel, BorderLayout.WEST);
            searchPanel.add(searchField, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(searchPanel);

            JCheckBox selectAllCheckbox = new JCheckBox("Select all");
            selectAllCheckbox.setFont(new Font("Inter", Font.PLAIN, 12));
            selectAllCheckbox.setCursor(new Cursor(Cursor.HAND_CURSOR));
            selectAllCheckbox.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0));
            montoyaApi.userInterface().applyThemeToComponent(selectAllCheckbox);

            JPanel searchAndSelectAllPanel = new JPanel(new BorderLayout());
            searchAndSelectAllPanel.add(searchPanel, BorderLayout.CENTER);
            searchAndSelectAllPanel.add(selectAllCheckbox, BorderLayout.SOUTH);
            montoyaApi.userInterface().applyThemeToComponent(searchAndSelectAllPanel);

            topPanel.add(searchAndSelectAllPanel, BorderLayout.NORTH);

            // Tags panel with checkboxes
            JPanel tagsPanel = new JPanel(new GridBagLayout());
            montoyaApi.userInterface().applyThemeToComponent(tagsPanel);

            JScrollPane tagsScrollPane = new JScrollPane(tagsPanel);
            tagsScrollPane.setPreferredSize(new Dimension(DEFAULT_WIDTH - 50, 200));
            tagsScrollPane.setBorder(BorderFactory.createTitledBorder("Select Tags"));
            tagsScrollPane.getVerticalScrollBar().setUnitIncrement(16);
            montoyaApi.userInterface().applyThemeToComponent(tagsScrollPane);

            topPanel.add(tagsScrollPane, BorderLayout.CENTER);

            // Preview section
            JPanel previewPanel = new JPanel(new BorderLayout());
            previewPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

            previewArea = new JTextArea();
            previewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            previewArea.setEditable(false);
            montoyaApi.userInterface().applyThemeToComponent(previewArea);

            JScrollPane previewScrollPane = new JScrollPane(previewArea);
            previewScrollPane.setPreferredSize(new Dimension(DEFAULT_WIDTH - 50, 200));
            previewScrollPane.setBorder(BorderFactory.createTitledBorder("Preview"));
            montoyaApi.userInterface().applyThemeToComponent(previewScrollPane);

            previewPanel.add(previewScrollPane, BorderLayout.CENTER);

            // Button panel
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
            montoyaApi.userInterface().applyThemeToComponent(buttonPanel);

            // Add mode selection combo box
            JLabel modeLabel = new JLabel("Mode:");
            modeLabel.setFont(new Font("Inter", Font.PLAIN, 12));
            montoyaApi.userInterface().applyThemeToComponent(modeLabel);

            String[] modes = {"Convert", "Add tags"};
            modeComboBox = new JComboBox<>(modes);
            modeComboBox.setSelectedItem("Convert");
            modeComboBox.addActionListener(e -> updatePreview());
            montoyaApi.userInterface().applyThemeToComponent(modeComboBox);

            JButton previewButton = new JButton("Update Preview");
            previewButton.addActionListener(e -> updatePreview());
            montoyaApi.userInterface().applyThemeToComponent(previewButton);

            JButton sendToRepeaterButton = new JButton("Send to Repeater");
            sendToRepeaterButton.addActionListener(e -> sendToRepeater());
            montoyaApi.userInterface().applyThemeToComponent(sendToRepeaterButton);

            JButton sendToIntruderButton = new JButton("Send to Intruder");
            sendToIntruderButton.addActionListener(e -> sendToIntruder());
            montoyaApi.userInterface().applyThemeToComponent(sendToIntruderButton);

            JButton cancelButton = new JButton("Cancel");
            cancelButton.addActionListener(e -> window.dispose());
            montoyaApi.userInterface().applyThemeToComponent(cancelButton);

            JButton clearButton = new JButton("Clear");
            clearButton.addActionListener(e -> {
                for (JCheckBox checkbox : tagCheckboxes.values()) {
                    checkbox.setSelected(false);
                }
                selectedTags.clear();
                selectAllCheckbox.setSelected(false);
                previewArea.setText("");
            });
            montoyaApi.userInterface().applyThemeToComponent(clearButton);

            JButton copyButton = new JButton("Copy");
            copyButton.addActionListener(e -> {
                if (selectedTags.isEmpty()) {
                    return;
                }
                StringBuilder output = new StringBuilder();
                boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
                for (Tag tag : selectedTags) {
                    String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
                    String tagStart = tagStartEnd[0];
                    String tagEnd = tagStartEnd[1];
                    String taggedText = tagStart + selectedText + tagEnd;
                    String result;
                    if (shouldConvert) {
                        try {
                            result = HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor);
                        } catch (Exception ex) {
                            result = "Error: " + ex.getMessage();
                        }
                    } else {
                        result = taggedText;
                    }
                    output.append(result).append("\n");
                }
                StringSelection selection = new StringSelection(output.toString().trim());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(selection, null);
            });
            montoyaApi.userInterface().applyThemeToComponent(copyButton);

            buttonPanel.add(clearButton);
            buttonPanel.add(copyButton);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(modeLabel);
            buttonPanel.add(modeComboBox);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(previewButton);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(sendToRepeaterButton);
            buttonPanel.add(sendToIntruderButton);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(cancelButton);

            // Helper: Filter tags
            Function<String, ArrayList<Tag>> filterTags = searchText -> {
                ArrayList<Tag> filtered = new ArrayList<>();
                String lowerSearch = searchText.toLowerCase();
                for (Tag tag : tags) {
                    if (lowerSearch.isEmpty() ||
                        tag.name.toLowerCase().contains(lowerSearch) ||
                        tag.category.toString().toLowerCase().contains(lowerSearch) ||
                        (tag.tooltip != null && tag.tooltip.toLowerCase().contains(lowerSearch))) {
                        filtered.add(tag);
                    }
                }
                filtered.sort((a, b) -> a.name.compareToIgnoreCase(b.name));
                return filtered;
            };

            // Helper: Create tag checkbox
            Function<Tag, JPanel> createTagCheckbox = tag -> {
                JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                JCheckBox checkbox = new JCheckBox(tag.name);
                checkbox.setToolTipText(tag.tooltip != null ? tag.tooltip : tag.category.toString());
                checkbox.setFont(new Font("Inter", Font.PLAIN, 12));
                checkbox.setCursor(new Cursor(Cursor.HAND_CURSOR));

                montoyaApi.userInterface().applyThemeToComponent(checkbox);
                montoyaApi.userInterface().applyThemeToComponent(panel);

                tagCheckboxes.put(tag.name, checkbox);

                checkbox.addActionListener(e -> {
                    if (checkbox.isSelected()) {
                        if (!selectedTags.contains(tag)) {
                            selectedTags.add(tag);
                        }
                    } else {
                        selectedTags.remove(tag);
                    }
                    updatePreview();
                });

                panel.add(checkbox);
                return panel;
            };

            // Update tags display
            Runnable updateTags = () -> {
                tagsPanel.removeAll();
                tagCheckboxes.clear();

                ArrayList<Tag> filteredTags = filterTags.apply(searchField.getText());

                if (!filteredTags.isEmpty()) {
                    GridBagConstraints gbc = new GridBagConstraints();
                    gbc.insets = new Insets(3, 3, 3, 3);
                    gbc.anchor = GridBagConstraints.WEST;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.gridy = 0;

                    int currentColumn = 0;
                    for (Tag tag : filteredTags) {
                        JPanel tagPanel = createTagCheckbox.apply(tag);
                        gbc.gridx = currentColumn;
                        gbc.weightx = 1.0 / COLUMN_COUNT;
                        tagsPanel.add(tagPanel, gbc);

                        if (++currentColumn >= COLUMN_COUNT) {
                            currentColumn = 0;
                            gbc.gridy++;
                        }
                    }
                } else {
                    JLabel noResultsLabel = new JLabel("No tags found matching: " + searchField.getText());
                    noResultsLabel.setFont(new Font("Inter", Font.PLAIN, 13));
                    montoyaApi.userInterface().applyThemeToComponent(noResultsLabel);

                    GridBagConstraints gbc = new GridBagConstraints();
                    gbc.gridwidth = COLUMN_COUNT;
                    tagsPanel.add(noResultsLabel, gbc);
                }

                tagsPanel.revalidate();
                tagsPanel.repaint();
            };

            selectAllCheckbox.addActionListener(e -> {
                ArrayList<Tag> filteredTags = filterTags.apply(searchField.getText());
                boolean selectAll = selectAllCheckbox.isSelected();
                for (Tag tag : filteredTags) {
                    JCheckBox checkbox = tagCheckboxes.get(tag.name);
                    if (checkbox != null && checkbox.isSelected() != selectAll) {
                        checkbox.setSelected(selectAll);
                        if (selectAll) {
                            if (!selectedTags.contains(tag)) {
                                selectedTags.add(tag);
                            }
                        } else {
                            selectedTags.remove(tag);
                        }
                    }
                }
                updatePreview();
            });

            // Event listeners
            searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    selectAllCheckbox.setSelected(false);
                    updateTags.run();
                }
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    selectAllCheckbox.setSelected(false);
                    updateTags.run();
                }
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    selectAllCheckbox.setSelected(false);
                    updateTags.run();
                }
            });

            searchField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                        window.dispose();
                    }
                }
            });

            // Add window focus listener - dispose when focus is lost
            window.addWindowFocusListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowLostFocus(java.awt.event.WindowEvent e) {
                    window.dispose();
                }
            });

            // Assemble UI
            JPanel contentPanel = new JPanel(new BorderLayout());
            contentPanel.add(titlePanel, BorderLayout.NORTH);
            contentPanel.add(topPanel, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(contentPanel);

            mainPanel.add(contentPanel, BorderLayout.NORTH);
            mainPanel.add(previewPanel, BorderLayout.CENTER);
            mainPanel.add(buttonPanel, BorderLayout.SOUTH);

            // Initialize window
            applyRoundedCorners.run();
            window.add(mainPanel);

            // Apply theme to the window's content pane if available
            montoyaApi.userInterface().applyThemeToComponent(window.getContentPane());
            window.setLocationRelativeTo(montoyaApi.userInterface().swingUtils().suiteFrame());

            // Initialize content and show
            updateTags.run();
            window.setVisible(true);
            searchField.requestFocusInWindow();
        });
    }

    private void updatePreview() {
        if (selectedTags.isEmpty()) {
            previewArea.setText("No tags selected. Please select at least one tag.");
            return;
        }

        StringBuilder preview = new StringBuilder();
        preview.append("Selected text: ").append(selectedText).append("\n");
        preview.append("Mode: ").append(modeComboBox.getSelectedItem()).append("\n");
        preview.append("=====================================\n\n");

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());

        for (Tag tag : selectedTags) {
            String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
            String tagStart = tagStartEnd[0];
            String tagEnd = tagStartEnd[1];
            String taggedText = tagStart + selectedText + tagEnd;

            String result;
            if (shouldConvert) {
                // Process through Hackvertor to get actual encoded result
                try {
                    result = HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor);
                } catch (Exception ex) {
                    result = "Error: " + ex.getMessage();
                }
            } else {
                // Just add tags without converting
                result = taggedText;
            }

            preview.append("Tag: ").append(tag.name).append("\n");
            if (!shouldConvert) {
                preview.append("Tagged: ").append(result).append("\n");
            } else {
                preview.append("Input: ").append(taggedText).append("\n");
                preview.append("Result: ").append(result).append("\n");
            }
            preview.append("-------------------------------------\n");
        }

        previewArea.setText(preview.toString());
        previewArea.setCaretPosition(0);
    }

    private void sendToRepeater() {
        if (selectedTags.isEmpty()) {
            JOptionPane.showMessageDialog(window,
                "Please select at least one tag before sending to Repeater.",
                "No Tags Selected",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (messageEditor == null || baseRequestResponse == null) {
            JOptionPane.showMessageDialog(window,
                "Unable to access the original request.",
                "Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        HttpRequest baseRequest = baseRequestResponse.request();
        String requestStr = baseRequest.toString();
        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());

        for (Tag tag : selectedTags) {
            String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
            String tagStart = tagStartEnd[0];
            String tagEnd = tagStartEnd[1];
            String taggedText = tagStart + selectedText + tagEnd;

            String replacementText;
            if (shouldConvert) {
                // Process through Hackvertor to get actual encoded result
                try {
                    replacementText = HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor);
                } catch (Exception ex) {
                    replacementText = selectedText; // Fallback to original if error
                }
            } else {
                // Just add tags without converting
                replacementText = taggedText;
            }

            // Replace the selected text with the result
            String modifiedRequestStr = requestStr.replace(selectedText, replacementText);
            HttpRequest modifiedRequest = HttpRequest.httpRequest(modifiedRequestStr);

            // Send to Repeater with a descriptive tab name
            String modePrefix = shouldConvert ? "HV-" : "HVT-";
            String tabName = modePrefix + tag.name + "-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
            montoyaApi.repeater().sendToRepeater(modifiedRequest, tabName);
        }

        JOptionPane.showMessageDialog(window,
            "Sent " + selectedTags.size() + " requests to Repeater.",
            "Success",
            JOptionPane.INFORMATION_MESSAGE);

        window.dispose();
    }

    private void sendToIntruder() {
        if (selectedTags.isEmpty()) {
            JOptionPane.showMessageDialog(window,
                "Please select at least one tag before sending to Intruder.",
                "No Tags Selected",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (messageEditor == null || baseRequestResponse == null) {
            JOptionPane.showMessageDialog(window,
                "Unable to access the original request.",
                "Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        HttpRequest baseRequest = baseRequestResponse.request();
        String requestStr = baseRequest.toString();

        // Find the position of the selected text in the request
        int startPos = requestStr.indexOf(selectedText);
        int endPos = startPos + selectedText.length();

        if (startPos == -1) {
            JOptionPane.showMessageDialog(window,
                "Could not find the selected text in the request.",
                "Error",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        Range insertionPoint = Range.range(startPos, endPos);
        HttpRequestTemplate intruderTemplate = HttpRequestTemplate.httpRequestTemplate(baseRequest, Collections.singletonList(insertionPoint));
        String tabName = "HV-Multi-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
        montoyaApi.intruder().sendToIntruder(baseRequestResponse.request().httpService(), intruderTemplate, tabName);

        // Generate payload list for Intruder
        StringBuilder payloads = new StringBuilder();
        payloads.append("Hackvertor Multi-Encoder Payloads:\n");

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        payloads.append("Mode: ").append(modeComboBox.getSelectedItem()).append("\n");
        payloads.append("Copy these payloads to use in Intruder:\n\n");

        for (Tag tag : selectedTags) {
            String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
            String tagStart = tagStartEnd[0];
            String tagEnd = tagStartEnd[1];
            String taggedText = tagStart + selectedText + tagEnd;

            String payloadResult;
            if (shouldConvert) {
                // Process through Hackvertor to get actual encoded result
                try {
                    payloadResult = HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor);
                } catch (Exception ex) {
                    payloadResult = selectedText; // Fallback to original if error
                }
            } else {
                // Just add tags without converting
                payloadResult = taggedText;
            }

            payloads.append(payloadResult).append("\n");
        }

        // Show payloads in a window
        JTextArea payloadArea = new JTextArea(payloads.toString());
        payloadArea.setEditable(false);
        payloadArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(payloadArea);
        scrollPane.setPreferredSize(new Dimension(600, 400));

        JOptionPane.showMessageDialog(window,
            scrollPane,
            "Payloads for Intruder",
            JOptionPane.INFORMATION_MESSAGE);

        window.dispose();
    }
}