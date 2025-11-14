package burp.hv.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKeyEvent;
import burp.hv.HackvertorExtension;
import burp.hv.tags.Tag;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static burp.hv.utils.TagUtils.generateTagActionListener;

public class TagFinderWindow {
    private static final int DEFAULT_WIDTH = 750;
    private static final int DEFAULT_HEIGHT = 500;
    private static final int CORNER_RADIUS = 20;
    private static final int COLUMN_COUNT = 3;

    private static final Color COLOR_BACKGROUND = new Color(255, 255, 255);
    private static final Color COLOR_BORDER = new Color(229, 231, 235);
    private static final Color COLOR_TEXT = new Color(55, 65, 81);
    private static final Color COLOR_TEXT_HOVER = new Color(99, 102, 241);
    private static final Color COLOR_TEXT_MUTED = new Color(156, 163, 175);
    private static final Color COLOR_LABEL = new Color(107, 114, 128);
    private static final Color COLOR_INPUT_BORDER = new Color(209, 213, 219);

    private final MontoyaApi montoyaApi;
    private final HotKeyEvent event;
    private final ArrayList<Tag> tags;
    private final BiConsumer<String, JWindow> onTagSelected;
    private final int windowWidth;
    private final int windowHeight;

    public TagFinderWindow(MontoyaApi montoyaApi, HotKeyEvent event, ArrayList<Tag> tags,
                          BiConsumer<String, JWindow> onTagSelected) {
        this(montoyaApi, event, tags, onTagSelected, DEFAULT_WIDTH, DEFAULT_HEIGHT);
    }

    public TagFinderWindow(MontoyaApi montoyaApi, HotKeyEvent event, ArrayList<Tag> tags,
                          BiConsumer<String, JWindow> onTagSelected, int width, int height) {
        this.montoyaApi = montoyaApi;
        this.event = event;
        this.tags = tags;
        this.onTagSelected = onTagSelected;
        this.windowWidth = width;
        this.windowHeight = height;
    }

    public void show() {
        SwingUtilities.invokeLater(() -> {
            final Tag[] firstVisibleTag = {null};

            // Create window
            JWindow findTagWindow = new JWindow(montoyaApi.userInterface().swingUtils().suiteFrame());
            findTagWindow.setLayout(new BorderLayout());
            findTagWindow.setSize(windowWidth, windowHeight);

            // Apply rounded corners
            Runnable applyRoundedCorners = () -> {
                try {
                    findTagWindow.setBackground(new Color(0, 0, 0, 0));
                    SwingUtilities.invokeLater(() -> {
                        Shape shape = new RoundRectangle2D.Float(0, 0, windowWidth, windowHeight,
                                                                 CORNER_RADIUS, CORNER_RADIUS);
                        findTagWindow.setShape(shape);
                    });
                } catch (UnsupportedOperationException ignored) {}
            };

            // Create search field
            JTextField searchField = new JTextField();
            searchField.setFont(new Font("Monospaced", Font.PLAIN, 14));
            searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_INPUT_BORDER, 1),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
            ));

            // Create tags panel
            JPanel tagsPanel = new JPanel(new GridBagLayout());
            tagsPanel.setOpaque(true);
            tagsPanel.setBackground(COLOR_BACKGROUND);

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

            // Helper: Create tag button
            Function<Tag, JButton> createTagButton = tag -> {
                JButton button = new JButton(tag.name);
                button.setToolTipText(tag.tooltip != null ? tag.tooltip : tag.category.toString());
                button.setFont(new Font("Inter", Font.PLAIN, 12));
                button.setCursor(new Cursor(Cursor.HAND_CURSOR));
                button.setFocusPainted(false);
                button.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
                button.setContentAreaFilled(false);
                button.setBorderPainted(false);
                button.setOpaque(false);
                button.setForeground(COLOR_TEXT);

                button.addMouseListener(new java.awt.event.MouseAdapter() {
                    public void mouseEntered(java.awt.event.MouseEvent evt) {
                        button.setForeground(COLOR_TEXT_HOVER);
                    }
                    public void mouseExited(java.awt.event.MouseEvent evt) {
                        button.setForeground(COLOR_TEXT);
                    }
                });

                button.addActionListener(e -> {
                    generateTagActionListener(event, tag).actionPerformed(null);
                    HackvertorExtension.lastTagUsed = tag.name;
                    findTagWindow.dispose();
                });

                return button;
            };

            // Update tags display
            Runnable updateTags = () -> {
                tagsPanel.removeAll();
                firstVisibleTag[0] = null;

                ArrayList<Tag> filteredTags = filterTags.apply(searchField.getText());

                if (!filteredTags.isEmpty()) {
                    firstVisibleTag[0] = filteredTags.get(0);

                    GridBagConstraints gbc = new GridBagConstraints();
                    gbc.insets = new Insets(3, 3, 3, 3);
                    gbc.anchor = GridBagConstraints.WEST;
                    gbc.fill = GridBagConstraints.HORIZONTAL;
                    gbc.gridy = 0;

                    int currentColumn = 0;
                    for (Tag tag : filteredTags) {
                        JButton tagButton = createTagButton.apply(tag);
                        gbc.gridx = currentColumn;
                        gbc.weightx = 1.0 / COLUMN_COUNT;
                        tagsPanel.add(tagButton, gbc);

                        if (++currentColumn >= COLUMN_COUNT) {
                            currentColumn = 0;
                            gbc.gridy++;
                        }
                    }
                } else {
                    JLabel noResultsLabel = new JLabel("No tags found matching: " + searchField.getText());
                    noResultsLabel.setForeground(COLOR_TEXT_MUTED);
                    noResultsLabel.setFont(new Font("Inter", Font.PLAIN, 13));

                    GridBagConstraints gbc = new GridBagConstraints();
                    gbc.gridwidth = COLUMN_COUNT;
                    tagsPanel.add(noResultsLabel, gbc);
                }

                tagsPanel.revalidate();
                tagsPanel.repaint();
            };

            // Build UI
            JPanel mainPanel = new JPanel(new BorderLayout());
            mainPanel.setBackground(COLOR_BACKGROUND);
            mainPanel.setOpaque(true);
            mainPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                BorderFactory.createEmptyBorder(14, 14, 14, 14)
            ));

            JPanel searchPanel = new JPanel(new BorderLayout());
            searchPanel.setBackground(COLOR_BACKGROUND);
            searchPanel.setOpaque(true);
            searchPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 12, 0));

            JLabel searchLabel = new JLabel("Search tags: ");
            searchLabel.setForeground(COLOR_LABEL);
            searchLabel.setFont(new Font("Inter", Font.PLAIN, 13));

            searchPanel.add(searchLabel, BorderLayout.WEST);
            searchPanel.add(searchField, BorderLayout.CENTER);

            JScrollPane scrollPane = new JScrollPane(tagsPanel);
            scrollPane.setPreferredSize(new Dimension(windowWidth - 50, windowHeight - 100));
            scrollPane.setBorder(BorderFactory.createEmptyBorder());
            scrollPane.getVerticalScrollBar().setUnitIncrement(16);

            mainPanel.add(searchPanel, BorderLayout.NORTH);
            mainPanel.add(scrollPane, BorderLayout.CENTER);

            // Event listeners
            searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                public void insertUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { updateTags.run(); }
            });

            searchField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                        findTagWindow.dispose();
                    } else if (e.getKeyCode() == KeyEvent.VK_ENTER && firstVisibleTag[0] != null) {
                        generateTagActionListener(event, firstVisibleTag[0]).actionPerformed(null);
                        HackvertorExtension.lastTagUsed = firstVisibleTag[0].name;
                        findTagWindow.dispose();
                    }
                }
            });

            findTagWindow.addWindowFocusListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowLostFocus(java.awt.event.WindowEvent e) {
                    findTagWindow.dispose();
                }
            });

            // Initialize window
            applyRoundedCorners.run();
            findTagWindow.add(mainPanel);
            findTagWindow.setLocationRelativeTo(montoyaApi.userInterface().swingUtils().suiteFrame());
            updateTags.run();
            findTagWindow.setVisible(true);
            searchField.requestFocusInWindow();
        });
    }
}