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
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.text.*;
import java.util.EnumSet;
import java.util.Set;
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
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class MultiEncoderWindow {
    private static final int DEFAULT_WIDTH = 900;
    private static final int DEFAULT_HEIGHT = 600;
    private static final int CORNER_RADIUS = 20;
    private static final int COLUMN_COUNT = 3;
    private static final int MAX_VARIANTS_DISPLAY = 100;
    private static final int MAX_VARIANTS_TOTAL = 10000;
    private static final int MAX_TAGS_PER_LAYER = 50;
    private static final int CONVERT_TIMEOUT_SECONDS = 20;
    private static final Set<Tag.Category> DANGEROUS_CATEGORIES = EnumSet.of(
            Tag.Category.Custom,
            Tag.Category.System,
            Tag.Category.Languages
    );
    private static final String PERSISTENCE_KEY = "multiEncoderState";

    private final MontoyaApi montoyaApi;
    private final String selectedText;
    private final ArrayList<Tag> tags;
    private final MessageEditorHttpRequestResponse messageEditor;
    private final HttpRequestResponse baseRequestResponse;
    private final ArrayList<Layer> layers;
    private final Consumer<String> hackvertorCallback;
    private JTextPane previewArea;
    private JTextField previewSearchField;
    private String lastPreviewContent = "";
    private JWindow window;
    private JComboBox<String> modeComboBox;
    private JTabbedPane layerTabbedPane;
    private int layerCounter = 1;
    private JLabel statusLabel;
    private Timer statusClearTimer;
    private final Set<Tag.Category> enabledDangerousCategories = EnumSet.noneOf(Tag.Category.class);
    private final Map<Tag.Category, JCheckBox> dangerousCategoryCheckboxes = new HashMap<>();

    private class Layer {
        final Map<String, JCheckBox> tagCheckboxes;
        final ArrayList<Tag> selectedTags;
        final JPanel tagsPanel;
        final JTextField searchField;
        final JCheckBox selectAllCheckbox;
        Runnable updateTags;

        Layer(JPanel tagsPanel, JTextField searchField, JCheckBox selectAllCheckbox) {
            this.tagCheckboxes = new HashMap<>();
            this.selectedTags = new ArrayList<>();
            this.tagsPanel = tagsPanel;
            this.searchField = searchField;
            this.selectAllCheckbox = selectAllCheckbox;
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

            loadState();

            JPanel dangerousCategoriesPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JLabel dangerousLabel = new JLabel("Enable dangerous categories:");
            dangerousLabel.setFont(new Font("Inter", Font.PLAIN, 12));
            montoyaApi.userInterface().applyThemeToComponent(dangerousLabel);
            dangerousCategoriesPanel.add(dangerousLabel);

            for (Tag.Category category : DANGEROUS_CATEGORIES) {
                JCheckBox categoryCheckbox = new JCheckBox(category.name());
                categoryCheckbox.setFont(new Font("Inter", Font.PLAIN, 12));
                categoryCheckbox.setCursor(new Cursor(Cursor.HAND_CURSOR));
                categoryCheckbox.setToolTipText("Enable " + category.name() + " tags (may execute code)");
                categoryCheckbox.setSelected(enabledDangerousCategories.contains(category));
                categoryCheckbox.addActionListener(e -> {
                    if (categoryCheckbox.isSelected()) {
                        enabledDangerousCategories.add(category);
                    } else {
                        enabledDangerousCategories.remove(category);
                    }
                    refreshAllLayers();
                });
                montoyaApi.userInterface().applyThemeToComponent(categoryCheckbox);
                dangerousCategoriesPanel.add(categoryCheckbox);
                dangerousCategoryCheckboxes.put(category, categoryCheckbox);
            }
            montoyaApi.userInterface().applyThemeToComponent(dangerousCategoriesPanel);

            JPanel layerControlPanel = new JPanel(new BorderLayout());
            layerControlPanel.add(layerButtonPanel, BorderLayout.WEST);
            layerControlPanel.add(dangerousCategoriesPanel, BorderLayout.EAST);
            montoyaApi.userInterface().applyThemeToComponent(layerControlPanel);

            topPanel.add(layerControlPanel, BorderLayout.NORTH);
            topPanel.add(layerTabbedPane, BorderLayout.CENTER);

            JPanel previewPanel = new JPanel(new BorderLayout());
            previewPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));

            JPanel previewSearchPanel = new JPanel(new BorderLayout(5, 0));
            previewSearchPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
            JLabel previewSearchLabel = new JLabel("Filter:");
            previewSearchLabel.setFont(new Font("Inter", Font.PLAIN, 12));
            montoyaApi.userInterface().applyThemeToComponent(previewSearchLabel);
            previewSearchField = new JTextField();
            previewSearchField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            previewSearchField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyReleased(KeyEvent e) {
                    applyPreviewFilter();
                }
            });
            montoyaApi.userInterface().applyThemeToComponent(previewSearchField);
            previewSearchPanel.add(previewSearchLabel, BorderLayout.WEST);
            previewSearchPanel.add(previewSearchField, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(previewSearchPanel);

            previewArea = new JTextPane();
            previewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            previewArea.setEditable(false);
            montoyaApi.userInterface().applyThemeToComponent(previewArea);

            JScrollPane previewScrollPane = new JScrollPane(previewArea);
            previewScrollPane.setPreferredSize(new Dimension(DEFAULT_WIDTH - 50, 180));
            previewScrollPane.setBorder(BorderFactory.createTitledBorder("Preview"));
            montoyaApi.userInterface().applyThemeToComponent(previewScrollPane);

            previewPanel.add(previewSearchPanel, BorderLayout.NORTH);
            previewPanel.add(previewScrollPane, BorderLayout.CENTER);

            statusLabel = new JLabel(" ");
            statusLabel.setFont(new Font("Inter", Font.BOLD, 12));
            statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
            statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
            montoyaApi.userInterface().applyThemeToComponent(statusLabel);

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
                lastPreviewContent = "";
                previewSearchField.setText("");
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
                    saveState();
                    window.dispose();
                }
            });

            JPanel contentPanel = new JPanel(new BorderLayout());
            contentPanel.add(titlePanel, BorderLayout.NORTH);
            contentPanel.add(topPanel, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(contentPanel);

            JPanel southPanel = new JPanel(new BorderLayout());
            southPanel.add(statusLabel, BorderLayout.NORTH);
            southPanel.add(buttonPanel, BorderLayout.CENTER);
            montoyaApi.userInterface().applyThemeToComponent(southPanel);

            mainPanel.add(contentPanel, BorderLayout.NORTH);
            mainPanel.add(previewPanel, BorderLayout.CENTER);
            mainPanel.add(southPanel, BorderLayout.SOUTH);

            applyRoundedCorners.run();
            window.add(mainPanel);

            montoyaApi.userInterface().applyThemeToComponent(window.getContentPane());
            window.setLocationRelativeTo(montoyaApi.userInterface().swingUtils().suiteFrame());

            int savedLayerCount = getSavedLayerCount();
            int layersToCreate = Math.max(1, savedLayerCount);
            for (int i = 0; i < layersToCreate; i++) {
                addLayer();
                if (i < savedLayerCount) {
                    loadLayerState(layers.get(i), i);
                }
            }
            updatePreview();

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

        Layer layer = new Layer(tagsPanel, searchField, selectAllCheckbox);

        Function<String, ArrayList<Tag>> filterTags = searchText -> {
            ArrayList<Tag> filtered = new ArrayList<>();
            String lowerSearch = searchText.toLowerCase();
            for (Tag tag : tags) {
                if (DANGEROUS_CATEGORIES.contains(tag.category) &&
                    !enabledDangerousCategories.contains(tag.category)) {
                    continue;
                }
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

        layer.updateTags = updateTags;

        java.awt.event.ActionListener selectAllListener = new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                ArrayList<Tag> filteredTags = filterTags.apply(searchField.getText());
                boolean selectAll = selectAllCheckbox.isSelected();

                if (selectAll && filteredTags.size() > MAX_TAGS_PER_LAYER) {
                    showWarningMessage("Too many tags (" + filteredTags.size() + "). Max is " + MAX_TAGS_PER_LAYER + ". Use search to filter.");
                }

                int count = 0;
                for (Tag tag : filteredTags) {
                    if (selectAll && count >= MAX_TAGS_PER_LAYER) {
                        break;
                    }
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
                    count++;
                }
                updatePreview();
            }
        };
        selectAllCheckbox.addActionListener(selectAllListener);

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

    private void refreshAllLayers() {
        for (Layer layer : layers) {
            layer.selectedTags.removeIf(tag ->
                    DANGEROUS_CATEGORIES.contains(tag.category) &&
                    !enabledDangerousCategories.contains(tag.category)
            );
            layer.updateTags.run();
        }
        updatePreview();
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

    private void showStatusMessage(String message, Color color) {
        if (statusClearTimer != null && statusClearTimer.isRunning()) {
            statusClearTimer.stop();
        }
        statusLabel.setText(message);
        statusLabel.setForeground(color);
        statusClearTimer = new Timer(5000, e -> {
            statusLabel.setText(" ");
            statusClearTimer.stop();
        });
        statusClearTimer.setRepeats(false);
        statusClearTimer.start();
    }

    private void showWarningMessage(String message) {
        showStatusMessage("⚠ " + message, new Color(255, 165, 0));
    }

    private void showInfoMessage(String message) {
        showStatusMessage("✓ " + message, new Color(0, 128, 0));
    }

    private void showErrorMessage(String message) {
        showStatusMessage("✗ " + message, new Color(200, 0, 0));
    }

    private String convertWithTimeout(String taggedText) {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<String> future = executor.submit(() ->
            HackvertorExtension.hackvertor.convert(taggedText, HackvertorExtension.hackvertor)
        );

        try {
            return future.get(CONVERT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            return "Error: Conversion timed out after " + CONVERT_TIMEOUT_SECONDS + " seconds";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        } finally {
            executor.shutdownNow();
        }
    }

    private int calculateTotalVariants() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            return 1;
        }
        int total = 1;
        for (ArrayList<Tag> layerTags : allLayerTags) {
            int layerSize = Math.min(layerTags.size(), MAX_TAGS_PER_LAYER);
            if (total > MAX_VARIANTS_TOTAL / layerSize) {
                return MAX_VARIANTS_TOTAL + 1;
            }
            total *= layerSize;
        }
        return total;
    }

    private ArrayList<String> generateAllVariants(String input, boolean shouldConvert) {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            ArrayList<String> result = new ArrayList<>();
            result.add(input);
            return result;
        }

        int estimatedTotal = calculateTotalVariants();
        if (estimatedTotal > MAX_VARIANTS_TOTAL) {
            ArrayList<String> result = new ArrayList<>();
            result.add("Error: Too many variants (" + estimatedTotal + "+). Maximum allowed is " + MAX_VARIANTS_TOTAL + ". Please reduce tag selection.");
            return result;
        }

        ArrayList<String> currentVariants = new ArrayList<>();
        currentVariants.add(input);

        for (ArrayList<Tag> layerTags : allLayerTags) {
            ArrayList<String> newVariants = new ArrayList<>();
            int tagCount = 0;
            for (String variant : currentVariants) {
                for (Tag tag : layerTags) {
                    if (tagCount >= MAX_TAGS_PER_LAYER) {
                        break;
                    }
                    if (newVariants.size() >= MAX_VARIANTS_TOTAL) {
                        break;
                    }
                    String[] tagStartEnd = Convertors.generateTagStartEnd(tag);
                    String taggedText = tagStartEnd[0] + variant + tagStartEnd[1];

                    if (shouldConvert) {
                        String converted = convertWithTimeout(taggedText);
                        newVariants.add(converted);
                    } else {
                        newVariants.add(taggedText);
                    }
                    tagCount++;
                }
                if (newVariants.size() >= MAX_VARIANTS_TOTAL) {
                    break;
                }
                tagCount = 0;
            }
            if (newVariants.size() >= MAX_VARIANTS_TOTAL) {
                currentVariants = newVariants;
                break;
            }
            currentVariants = newVariants;
        }

        return currentVariants;
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
        ArrayList<String> variants = generateAllVariants(selectedText, shouldConvert);
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < variants.size(); i++) {
            if (i > 0) output.append("\n");
            output.append(variants.get(i));
        }
        StringSelection selection = new StringSelection(output.toString());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);
    }

    private void updatePreview() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            lastPreviewContent = "No tags selected. Please select at least one tag in any layer.";
            previewArea.setText(lastPreviewContent);
            return;
        }

        StringBuilder preview = new StringBuilder();
        preview.append("Selected text: ").append(selectedText).append("\n");
        preview.append("Mode: ").append(modeComboBox.getSelectedItem()).append("\n");
        preview.append("=====================================\n\n");
        preview.append(getLayersSummary());

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        ArrayList<String> taggedVariants = generateAllVariants(selectedText, false);
        ArrayList<String> resultVariants = generateAllVariants(selectedText, shouldConvert);

        preview.append("Total variants: ").append(resultVariants.size()).append("\n");
        if (resultVariants.size() > MAX_VARIANTS_DISPLAY) {
            preview.append("Showing first ").append(MAX_VARIANTS_DISPLAY).append(" variants\n");
        }
        preview.append("=====================================\n\n");

        int displayLimit = Math.min(resultVariants.size(), MAX_VARIANTS_DISPLAY);
        for (int i = 0; i < displayLimit; i++) {
            preview.append("Variant ").append(i + 1).append(":\n");
            if (!shouldConvert) {
                preview.append("Tagged: ").append(resultVariants.get(i)).append("\n");
            } else {
                preview.append("Input: ").append(taggedVariants.get(i)).append("\n");
                preview.append("Result: ").append(resultVariants.get(i)).append("\n");
            }
            preview.append("-------------------------------------\n");
        }

        if (resultVariants.size() > MAX_VARIANTS_DISPLAY) {
            preview.append("\n... ").append(resultVariants.size() - MAX_VARIANTS_DISPLAY)
                   .append(" more variants not shown ...\n");
        }

        lastPreviewContent = preview.toString();
        applyPreviewFilter();
    }

    private void applyPreviewFilter() {
        String filterText = previewSearchField.getText().toLowerCase();
        StyledDocument doc = previewArea.getStyledDocument();

        Style defaultStyle = previewArea.addStyle("default", null);
        StyleConstants.setBackground(defaultStyle, previewArea.getBackground());

        Style highlightStyle = previewArea.addStyle("highlight", null);
        StyleConstants.setBackground(highlightStyle, new Color(255, 255, 0));
        StyleConstants.setForeground(highlightStyle, Color.BLACK);

        if (filterText.isEmpty()) {
            previewArea.setText(lastPreviewContent);
            previewArea.setCaretPosition(0);
            return;
        }

        String[] lines = lastPreviewContent.split("\n");
        StringBuilder filteredContent = new StringBuilder();
        ArrayList<int[]> highlights = new ArrayList<>();

        for (String line : lines) {
            if (line.toLowerCase().contains(filterText)) {
                int lineStart = filteredContent.length();
                filteredContent.append(line).append("\n");

                String lowerLine = line.toLowerCase();
                int searchStart = 0;
                int idx;
                while ((idx = lowerLine.indexOf(filterText, searchStart)) != -1) {
                    highlights.add(new int[]{lineStart + idx, filterText.length()});
                    searchStart = idx + 1;
                }
            }
        }

        if (filteredContent.isEmpty()) {
            previewArea.setText("No matches found for: " + previewSearchField.getText());
            return;
        }

        previewArea.setText(filteredContent.toString());

        for (int[] highlight : highlights) {
            doc.setCharacterAttributes(highlight[0], highlight[1], highlightStyle, false);
        }

        previewArea.setCaretPosition(0);
    }

    private void sendToHackvertor() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            showWarningMessage("Please select at least one tag before sending to Hackvertor.");
            return;
        }

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        ArrayList<String> variants = generateAllVariants(selectedText, shouldConvert);

        if (hackvertorCallback != null) {
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < variants.size(); i++) {
                if (i > 0) output.append("\n");
                output.append(variants.get(i));
            }
            hackvertorCallback.accept(output.toString());
        }

        window.dispose();
    }

    private void sendToRepeater() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            showWarningMessage("Please select at least one tag before sending to Repeater.");
            return;
        }

        if (messageEditor == null || baseRequestResponse == null) {
            showErrorMessage("Unable to access the original request.");
            return;
        }

        HttpRequest baseRequest = baseRequestResponse.request();
        String requestStr = baseRequest.toString();
        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        ArrayList<String> variants = generateAllVariants(selectedText, shouldConvert);

        String modePrefix = shouldConvert ? "HV-" : "HVT-";
        ArrayList<Tag> layer1Tags = allLayerTags.get(0);
        int variantsPerLayer1Tag = variants.size() / layer1Tags.size();
        for (int i = 0; i < variants.size(); i++) {
            String variant = variants.get(i);
            String modifiedRequestStr = requestStr.replace(selectedText, variant);
            HttpRequest modifiedRequest = HttpRequest.httpRequest(modifiedRequestStr);
            int layer1TagIndex = i / variantsPerLayer1Tag;
            String layer1TagName = layer1Tags.get(layer1TagIndex).name;
            String tabName = modePrefix + layer1TagName + "-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
            montoyaApi.repeater().sendToRepeater(modifiedRequest, tabName);
        }

        showInfoMessage("Sent " + variants.size() + " variant(s) to Repeater.");
        window.dispose();
    }

    private void sendToIntruder() {
        ArrayList<ArrayList<Tag>> allLayerTags = getAllLayerTags();
        if (allLayerTags.isEmpty()) {
            showWarningMessage("Please select at least one tag before sending to Intruder.");
            return;
        }

        if (messageEditor == null || baseRequestResponse == null) {
            showErrorMessage("Unable to access the original request.");
            return;
        }

        HttpRequest baseRequest = baseRequestResponse.request();
        String requestStr = baseRequest.toString();

        int startPos = requestStr.indexOf(selectedText);
        int endPos = startPos + selectedText.length();

        if (startPos == -1) {
            showErrorMessage("Could not find the selected text in the request.");
            return;
        }

        Range insertionPoint = Range.range(startPos, endPos);
        HttpRequestTemplate intruderTemplate = HttpRequestTemplate.httpRequestTemplate(baseRequest, Collections.singletonList(insertionPoint));
        String tabName = "HV-Layers-" + selectedText.substring(0, Math.min(selectedText.length(), 10));
        montoyaApi.intruder().sendToIntruder(baseRequestResponse.request().httpService(), intruderTemplate, tabName);

        boolean shouldConvert = "Convert".equals(modeComboBox.getSelectedItem());
        ArrayList<String> variants = generateAllVariants(selectedText, shouldConvert);

        StringBuilder payloadList = new StringBuilder();
        for (String variant : variants) {
            payloadList.append(variant).append("\n");
        }

        StringSelection selection = new StringSelection(payloadList.toString());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);

        JOptionPane.showMessageDialog(window, "Sent to Intruder. " + variants.size() + " payload(s) copied to clipboard.", "Success", JOptionPane.INFORMATION_MESSAGE);
        window.dispose();
    }

    private void saveState() {
        try {
            JSONObject state = new JSONObject();

            JSONArray enabledCategories = new JSONArray();
            for (Tag.Category category : enabledDangerousCategories) {
                enabledCategories.put(category.name());
            }
            state.put("enabledDangerousCategories", enabledCategories);

            JSONArray layersArray = new JSONArray();
            for (Layer layer : layers) {
                JSONObject layerObj = new JSONObject();
                layerObj.put("searchText", layer.searchField.getText());

                JSONArray selectedTagNames = new JSONArray();
                for (Tag tag : layer.selectedTags) {
                    selectedTagNames.put(tag.name);
                }
                layerObj.put("selectedTags", selectedTagNames);

                layersArray.put(layerObj);
            }
            state.put("layers", layersArray);

            montoyaApi.persistence().extensionData().setString(PERSISTENCE_KEY, state.toString());
        } catch (Exception e) {
            System.err.println("Failed to save MultiEncoder state: " + e.getMessage());
        }
    }

    private void loadState() {
        try {
            String content = montoyaApi.persistence().extensionData().getString(PERSISTENCE_KEY);
            if (content == null || content.isEmpty()) {
                return;
            }

            JSONObject state = new JSONObject(content);

            if (state.has("enabledDangerousCategories")) {
                JSONArray enabledCategories = state.getJSONArray("enabledDangerousCategories");
                for (int i = 0; i < enabledCategories.length(); i++) {
                    String categoryName = enabledCategories.getString(i);
                    try {
                        Tag.Category category = Tag.Category.valueOf(categoryName);
                        if (DANGEROUS_CATEGORIES.contains(category)) {
                            enabledDangerousCategories.add(category);
                        }
                    } catch (IllegalArgumentException ignored) {
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load MultiEncoder state: " + e.getMessage());
        }
    }

    private void loadLayerState(Layer layer, int layerIndex) {
        try {
            String content = montoyaApi.persistence().extensionData().getString(PERSISTENCE_KEY);
            if (content == null || content.isEmpty()) {
                return;
            }

            JSONObject state = new JSONObject(content);
            if (!state.has("layers")) {
                return;
            }

            JSONArray layersArray = state.getJSONArray("layers");
            if (layerIndex >= layersArray.length()) {
                return;
            }

            JSONObject layerObj = layersArray.getJSONObject(layerIndex);

            if (layerObj.has("searchText")) {
                layer.searchField.setText(layerObj.getString("searchText"));
            }

            if (layerObj.has("selectedTags")) {
                JSONArray selectedTagNames = layerObj.getJSONArray("selectedTags");
                for (int i = 0; i < selectedTagNames.length(); i++) {
                    String tagName = selectedTagNames.getString(i);
                    JCheckBox checkbox = layer.tagCheckboxes.get(tagName);
                    if (checkbox != null) {
                        checkbox.setSelected(true);
                        for (Tag tag : tags) {
                            if (tag.name.equals(tagName)) {
                                if (!layer.selectedTags.contains(tag)) {
                                    layer.selectedTags.add(tag);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load layer state: " + e.getMessage());
        }
    }

    private int getSavedLayerCount() {
        try {
            String content = montoyaApi.persistence().extensionData().getString(PERSISTENCE_KEY);
            if (content == null || content.isEmpty()) {
                return 0;
            }

            JSONObject state = new JSONObject(content);
            if (!state.has("layers")) {
                return 0;
            }

            return state.getJSONArray("layers").length();
        } catch (Exception e) {
            return 0;
        }
    }
}
