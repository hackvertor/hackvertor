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
import java.util.function.Consumer;
import java.util.function.Function;

public class MultiEncoderWindow {
    private static final int DEFAULT_WIDTH = 900;
    private static final int DEFAULT_HEIGHT = 600;
    private static final int CORNER_RADIUS = 20;
    private static final int COLUMN_COUNT = 3;

    private final MontoyaApi montoyaApi;
    private final String selectedText;
    private final ArrayList<Tag> tags;
    private final MessageEditorHttpRequestResponse messageEditor;
    private final HttpRequestResponse baseRequestResponse;
    private final ArrayList<Layer> layers;
    private final Consumer<String> hackvertorCallback;
    private JTextArea previewArea;
    private JWindow window;
    private JComboBox<String> modeComboBox;
    private JTabbedPane layerTabbedPane;
    private int layerCounter = 1;

    private class Layer {
        final Map<String, JCheckBox> tagCheckboxes;
        final ArrayList<Tag> selectedTags;
        final JPanel tagsPanel;
        final JTextField searchField;
        final JCheckBox selectAllCheckbox;
        final Runnable updateTags;

        Layer(JPanel tagsPanel, JTextField searchField, JCheckBox selectAllCheckbox, Runnable updateTags) {
            this.tagCheckboxes = new HashMap<>();
            this.selectedTags = new ArrayList<>();
            this.tagsPanel = tagsPanel;
            this.searchField = searchField;
            this.selectAllCheckbox = selectAllCheckbox;
            this.updateTags = updateTags;
        }
    }

    public MultiEncoderWindow(MontoyaApi montoyaApi, String selectedText, ArrayList<Tag> tags,
                              MessageEditorHttpRequestResponse messageEditor, HttpRequestResponse baseRequestResponse) {
        this(montoyaApi, selectedText, tags, messageEditor, baseRequestResponse, null);
    }

    public MultiEncoderWindow(MontoyaApi montoyaApi, String selectedText, ArrayList<Tag> tags,
                              Consumer<String> hackvertorCallback) {
        this(montoyaApi, selectedText, tags, null, null, hackvertorCallback);
    }

    private MultiEncoderWindow(MontoyaApi montoyaApi, String selectedText, ArrayList<Tag> tags,
                               MessageEditorHttpRequestResponse messageEditor, HttpRequestResponse baseRequestResponse,
                               Consumer<String> hackvertorCallback) {
        this.montoyaApi = montoyaApi;
        this.selectedText = selectedText;
        this.tags = tags;
        this.messageEditor = messageEditor;
        this.baseRequestResponse = baseRequestResponse;
        this.hackvertorCallback = hackvertorCallback;
        this.layers = new ArrayList<>();
    }

    public void show() {
        SwingUtilities.invokeLater(() -> {
            window = new JWindow(montoyaApi.userInterface().swingUtils().suiteFrame());
            window.setLayout(new BorderLayout());
            window.setSize(DEFAULT_WIDTH, DEFAULT_HEIGHT);

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

            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.setBorder(new EmptyBorder(14, 14, 14, 14));
            montoyaApi.userInterface().applyThemeToComponent(mainPanel);

            JPanel titlePanel = new JPanel(new BorderLayout());
            JLabel titleLabel = new JLabel("Multi Encoder");
            titleLabel.setFont(new Font("Inter", Font.BOLD, 16));
            titlePanel.add(titleLabel, BorderLayout.WEST);
            titlePanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
            montoyaApi.userInterface().applyThemeToComponent(titlePanel);
            montoyaApi.userInterface().applyThemeToComponent(titleLabel);

            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));
            montoyaApi.userInterface().applyThemeToComponent(topPanel);

            layerTabbedPane = new JTabbedPane();
            layerTabbedPane.setPreferredSize(new Dimension(DEFAULT_WIDTH - 50, 220));
            montoyaApi.userInterface().applyThemeToComponent(layerTabbedPane);

            JPanel layerButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton addLayerButton = new JButton("+ Add Layer");
            addLayerButton.addActionListener(e -> addLayer());
            montoyaApi.userInterface().applyThemeToComponent(addLayerButton);

            JButton removeLayerButton = new JButton("- Remove Layer");
            removeLayerButton.addActionListener(e -> removeCurrentLayer());
            montoyaApi.userInterface().applyThemeToComponent(removeLayerButton);

            layerButtonPanel.add(addLayerButton);
            layerButtonPanel.add(removeLayerButton);
            montoyaApi.userInterface().applyThemeToComponent(layerButtonPanel);

            topPanel.add(layerButtonPanel, BorderLayout.NORTH);
            topPanel.add(layerTabbedPane, BorderLayout.CENTER);

            JPanel previewPanel = new JPanel(new BorderLayout());
            previewPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

            previewArea = new JTextArea();
            previewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            previewArea.setEditable(false);
            montoyaApi.userInterface().applyThemeToComponent(previewArea);

            JScrollPane previewScrollPane = new JScrollPane(previewArea);
            previewScrollPane.setPreferredSize(new Dimension(DEFAULT_WIDTH - 50, 180));
            previewScrollPane.setBorder(BorderFactory.createTitledBorder("Preview"));
            montoyaApi.userInterface().applyThemeToComponent(previewScrollPane);

            previewPanel.add(previewScrollPane, BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
            montoyaApi.userInterface().applyThemeToComponent(buttonPanel);

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

            JButton cancelButton = new JButton("Cancel");
            cancelButton.addActionListener(e -> window.dispose());
            montoyaApi.userInterface().applyThemeToComponent(cancelButton);

            JButton clearButton = new JButton("Clear");
            clearButton.addActionListener(e -> {
                for (Layer layer : layers) {
                    for (JCheckBox checkbox : layer.tagCheckboxes.values()) {
                        checkbox.setSelected(false);
                    }
                    layer.selectedTags.clear();
                    layer.selectAllCheckbox.setSelected(false);
                }
                previewArea.setText("");
            });
            montoyaApi.userInterface().applyThemeToComponent(clearButton);

            JButton copyButton = new JButton("Copy");
            copyButton.addActionListener(e -> copyToClipboard());
            montoyaApi.userInterface().applyThemeToComponent(copyButton);

            buttonPanel.add(clearButton);
            buttonPanel.add(copyButton);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(modeLabel);
            buttonPanel.add(modeComboBox);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(previewButton);
            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));

            if (hackvertorCallback != null) {
                JButton sendToHackvertorButton = new JButton("Send to Hackvertor");
                sendToHackvertorButton.addActionListener(e -> sendToHackvertor());
                montoyaApi.userInterface().applyThemeToComponent(sendToHackvertorButton);
                buttonPanel.add(sendToHackvertorButton);
            } else {
                JButton sendToRepeaterButton = new JButton("Send to Repeater");
                sendToRepeaterButton.addActionListener(e -> sendToRepeater());
                montoyaApi.userInterface().applyThemeToComponent(sendToRepeaterButton);

                JButton sendToIntruderButton = new JButton("Send to Intruder");
                sendToIntruderButton.addActionListener(e -> sendToIntruder());
                montoyaApi.userInterface().applyThemeToComponent(sendToIntruderButton);

                buttonPanel.add(sendToRepeaterButton);
                buttonPanel.add(sendToIntruderButton);
            }

            buttonPanel.add(new JSeparator(SwingConstants.VERTICAL));
            buttonPanel.add(cancelButton);

            window.addWindowFocusListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowLostFocus(java.awt.event.WindowEvent e) {
                    window.dispose();
                }
            });

            JPanel contentPanel = new JPanel(new BorderLayout());
            contentPanel.add(titlePanel, BorderLayout.NORTH);
            contentPanel.add(topPanel, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(contentPanel);

            mainPanel.add(contentPanel, BorderLayout.NORTH);
            mainPanel.add(previewPanel, BorderLayout.CENTER);
            mainPanel.add(buttonPanel, BorderLayout.SOUTH);

            applyRoundedCorners.run();
            window.add(mainPanel);

            montoyaApi.userInterface().applyThemeToComponent(window.getContentPane());
            window.setLocationRelativeTo(montoyaApi.userInterface().swingUtils().suiteFrame());

            addLayer();

            window.setVisible(true);
            if (!layers.isEmpty()) {
                layers.get(0).searchField.requestFocusInWindow();
            }
        });
    }

    private void addLayer() {
        JPanel layerPanel = new JPanel(new BorderLayout());
        layerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        montoyaApi.userInterface().applyThemeToComponent(layerPanel);

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

        JPanel tagsPanel = new JPanel(new GridBagLayout());
        montoyaApi.userInterface().applyThemeToComponent(tagsPanel);

        JScrollPane tagsScrollPane = new JScrollPane(tagsPanel);
        tagsScrollPane.setBorder(BorderFactory.createTitledBorder("Select Tags"));
        tagsScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        montoyaApi.userInterface().applyThemeToComponent(tagsScrollPane);

        layerPanel.add(searchAndSelectAllPanel, BorderLayout.NORTH);
        layerPanel.add(tagsScrollPane, BorderLayout.CENTER);

        Layer layer = new Layer(tagsPanel, searchField, selectAllCheckbox, null);

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

        Function<Tag, JPanel> createTagCheckbox = tag -> {
            JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
            JCheckBox checkbox = new JCheckBox(tag.name);
            checkbox.setToolTipText(tag.tooltip != null ? tag.tooltip : tag.category.toString());
            checkbox.setFont(new Font("Inter", Font.PLAIN, 12));
            checkbox.setCursor(new Cursor(Cursor.HAND_CURSOR));

            montoyaApi.userInterface().applyThemeToComponent(checkbox);
            montoyaApi.userInterface().applyThemeToComponent(panel);

            layer.tagCheckboxes.put(tag.name, checkbox);

            checkbox.addActionListener(e -> {
                if (checkbox.isSelected()) {
                    if (!layer.selectedTags.contains(tag)) {
                        layer.selectedTags.add(tag);
                    }
                } else {
                    layer.selectedTags.remove(tag);
                }
                updatePreview();
            });

            panel.add(checkbox);
            return panel;
        };

        Runnable updateTags = () -> {
            tagsPanel.removeAll();
            layer.tagCheckboxes.clear();

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
                JCheckBox checkbox = layer.tagCheckboxes.get(tag.name);
                if (checkbox != null && checkbox.isSelected() != selectAll) {
                    checkbox.setSelected(selectAll);
                    if (selectAll) {
                        if (!layer.selectedTags.contains(tag)) {
                            layer.selectedTags.add(tag);
                        }
                    } else {
                        layer.selectedTags.remove(tag);
                    }
                }
            }
            updatePreview();
        });

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

        layers.add(layer);
        String tabTitle = "Layer " + layerCounter++;
        layerTabbedPane.addTab(tabTitle, layerPanel);
        layerTabbedPane.setSelectedIndex(layerTabbedPane.getTabCount() - 1);

        updateTags.run();
    }

    private void removeCurrentLayer() {
        if (layers.size() <= 1) {
            return;
        }
        int selectedIndex = layerTabbedPane.getSelectedIndex();
        if (selectedIndex >= 0 && selectedIndex < layers.size()) {
            layers.remove(selectedIndex);
            layerTabbedPane.removeTabAt(selectedIndex);
            updatePreview();
        }
    }

    private ArrayList<ArrayList<Tag>> getAllLayerTags() {
        ArrayList<ArrayList<Tag>> allLayerTags = new ArrayList<>();
        for (Layer layer : layers) {
            if (!layer.selectedTags.isEmpty()) {
                allLayerTags.add(new ArrayList<>(layer.selectedTags));
            }
        }
        return allLayerTags;
    }

    private String applyLayeredTags(String input, boolean shouldConvert) {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            return input;
        }

        StringBuilder tagStart = new StringBuilder();
        StringBuilder tagEnd = new StringBuilder();

        for (int i = allLayerTags.size() - 1; i >= 0; i--) {
            ArrayList<Tag> layerTags = allLayerTags.get(i);
            for (Tag tag : layerTags) {
                String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
                tagStart.append(tagStartEnd[0]);
                tagEnd.insert(0, tagStartEnd[1]);
            }
        }

        String taggedText = tagStart.toString() + input + tagEnd;

        if (shouldConvert) {
            try {
                return HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor);
            } catch (Exception ex) {
                return "Error: " + ex.getMessage();
            }
        }
        return taggedText;
    }

    private String getLayersSummary() {
        StringBuilder summary = new StringBuilder();
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        for (int i = 0; i < allLayerTags.size(); i++) {
            ArrayList<Tag> layerTags = allLayerTags.get(i);
            summary.append("Layer ").append(i + 1).append(": ");
            for (int j = 0; j < layerTags.size(); j++) {
                if (j > 0) summary.append(", ");
                summary.append(layerTags.get(j).name);
            }
            summary.append("\n");
        }
        return summary.toString();
    }

    private void copyToClipboard() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            return;
        }
        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        String result = applyLayeredTags(selectedText, shouldConvert);
        StringSelection selection = new StringSelection(result);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);
    }

    private void updatePreview() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            previewArea.setText("No tags selected. Please select at least one tag in any layer.");
            return;
        }

        StringBuilder preview = new StringBuilder();
        preview.append("Selected text: ").append(selectedText).append("\n");
        preview.append("Mode: ").append(modeComboBox.getSelectedItem()).append("\n");
        preview.append("=====================================\n\n");
        preview.append(getLayersSummary());
        preview.append("=====================================\n\n");

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        String taggedText = applyLayeredTags(selectedText, false);
        String result = applyLayeredTags(selectedText, shouldConvert);

        if (!shouldConvert) {
            preview.append("Tagged: ").append(result).append("\n");
        } else {
            preview.append("Input: ").append(taggedText).append("\n");
            preview.append("Result: ").append(result).append("\n");
        }

        previewArea.setText(preview.toString());
        previewArea.setCaretPosition(0);
    }

    private void sendToHackvertor() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            JOptionPane.showMessageDialog(window,
                "Please select at least one tag before sending to Hackvertor.",
                "No Tags Selected",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        String result = applyLayeredTags(selectedText, shouldConvert);

        if (hackvertorCallback != null) {
            hackvertorCallback.accept(result);
        }

        window.dispose();
    }

    private void sendToRepeater() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
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

        String replacementText = applyLayeredTags(selectedText, shouldConvert);
        String modifiedRequestStr = requestStr.replace(selectedText, replacementText);
        HttpRequest modifiedRequest = HttpRequest.httpRequest(modifiedRequestStr);

        String modePrefix = shouldConvert ? "HV-" : "HVT-";
        String tabName = modePrefix + "Layers-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
        montoyaApi.repeater().sendToRepeater(modifiedRequest, tabName);

        JOptionPane.showMessageDialog(window,
            "Sent request to Repeater.",
            "Success",
            JOptionPane.INFORMATION_MESSAGE);

        window.dispose();
    }

    private void sendToIntruder() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
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
        String tabName = "HV-Layers-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
        montoyaApi.intruder().sendToIntruder(baseRequestResponse.request().httpService(), intruderTemplate, tabName);

        StringBuilder payloads = new StringBuilder();
        payloads.append("Hackvertor Multi-Encoder Layered Payloads:\n");

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        payloads.append("Mode: ").append(modeComboBox.getSelectedItem()).append("\n");
        payloads.append(getLayersSummary());
        payloads.append("Copy this payload to use in Intruder:\n\n");

        String payloadResult = applyLayeredTags(selectedText, shouldConvert);
        payloads.append(payloadResult).append("\n");

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
