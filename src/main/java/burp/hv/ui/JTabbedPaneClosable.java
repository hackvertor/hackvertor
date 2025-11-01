package burp.hv.ui;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;

public class JTabbedPaneClosable extends JTabbedPane {
    public boolean clickedDelete = false;

    public JTabbedPaneClosable() {
        super();
    }

    @Override
    public void setSelectedIndex(int index) {
        // Hide close button for all tabs
        for (int i = 0; i < getTabCount(); i++) {
            Component tabComponent = getTabComponentAt(i);
            if (tabComponent instanceof CloseButtonTab) {
                ((CloseButtonTab) tabComponent).setCloseButtonVisible(false);
            }
        }

        // Call parent method to actually change selection
        super.setSelectedIndex(index);

        // Show close button for selected tab
        if (index >= 0 && index < getTabCount()) {
            Component tabComponent = getTabComponentAt(index);
            if (tabComponent instanceof CloseButtonTab) {
                ((CloseButtonTab) tabComponent).setCloseButtonVisible(true);
            }
        }
    }

    @Override
    public void addTab(String title, Icon icon, Component component, String tip) {
        super.addTab(title, icon, component, tip);
    }

    @Override
    public void addTab(String title, Icon icon, Component component) {
        addTab(title, icon, component, null);
    }

    @Override
    public void addTab(String title, Component component) {
        addTab(title, null, component);
    }

    @Override
    public void insertTab(String title, Icon icon, Component component, String tip, int index) {
        super.insertTab(title, icon, component, tip, index);
        if (!title.equals("...")) {
            CloseButtonTab closeTab = new CloseButtonTab(component, title, icon);
            setTabComponentAt(index, closeTab);
            // Show close button if this is the selected tab
            if (index == getSelectedIndex()) {
                closeTab.setCloseButtonVisible(true);
            }
        }
    }

    public void addTabNoExit(String title, Icon icon, Component component, String tip) {
        super.addTab(title, icon, component, tip);
    }

    public void addTabNoExit(String title, Icon icon, Component component) {
        addTabNoExit(title, icon, component, null);
    }

    public void addTabNoExit(String title, Component component) {
        addTabNoExit(title, null, component);
    }

    public String getActualTabTitle(int index) {
        Component tabComponent = getTabComponentAt(index);
        if (tabComponent instanceof CloseButtonTab) {
            CloseButtonTab closeTab = (CloseButtonTab) tabComponent;
            return closeTab.getTabTitle();
        }
        return getTitleAt(index);
    }

    public void setActualTabTitle(int index, String title) {
        Component tabComponent = getTabComponentAt(index);
        if (tabComponent instanceof CloseButtonTab) {
            CloseButtonTab closeTab = (CloseButtonTab) tabComponent;
            closeTab.setTabTitle(title);
        }
    }

    public class CloseButtonTab extends JPanel {
        private Component tab;
        private JTextField textField;
        private JLabel closeButton;

        public CloseButtonTab(final Component tab, String title, Icon icon) {
            this.tab = tab;
            setOpaque(false);
            setLayout(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.fill = GridBagConstraints.HORIZONTAL;
            c.anchor = GridBagConstraints.WEST;
            c.gridx = 0;
            c.gridy = 0;
            c.weightx = 1.0;
            c.gridwidth = 1;
            c.insets = new Insets(0, 0, 0, 10);

            textField = new JTextField(title);
            textField.setOpaque(false);
            textField.setBackground(new Color(0, 0, 0, 0));
            textField.setBorder(null);
            textField.setEditable(false);
            textField.setColumns(Math.max(title.length(), 1));

            textField.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        textField.setEditable(true);
                    }
                    if (e.getClickCount() == 1) {
                        JTabbedPaneClosable tabbedPane = (JTabbedPaneClosable) textField.getParent().getParent().getParent();
                        tabbedPane.setSelectedIndex(tabbedPane.indexOfComponent(tab));
                    }
                }
            });
            textField.addFocusListener(new FocusAdapter() {
                public void focusLost(FocusEvent e) {
                    textField.setEditable(false);
                    textField.setColumns(Math.max(textField.getText().length(), 1));
                    revalidate();
                }
            });

            // Update columns as user types
            textField.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) {
                    updateTextFieldSize();
                }
                public void removeUpdate(DocumentEvent e) {
                    updateTextFieldSize();
                }
                public void changedUpdate(DocumentEvent e) {
                    updateTextFieldSize();
                }
                private void updateTextFieldSize() {
                    SwingUtilities.invokeLater(() -> {
                        textField.setColumns(Math.max(textField.getText().length(), 1));
                        revalidate();
                    });
                }
            });

            add(textField, c);
            closeButton = new JLabel("x");
            closeButton.setFont(new Font("Courier", Font.PLAIN, 14));
            closeButton.setBorder(null);
            closeButton.addMouseListener(new CloseListener(tab));
            closeButton.setVisible(false);
            c.fill = GridBagConstraints.NONE;
            c.gridx = 1;
            c.weightx = 0;
            c.anchor = GridBagConstraints.EAST;
            c.insets = new Insets(0, 0, 0, 0);
            add(closeButton, c);
        }

        public String getTabTitle() {
            return textField.getText();
        }

        public void setTabTitle(String title) {
            textField.setText(title);
        }

        public void setCloseButtonVisible(boolean visible) {
            if (closeButton != null) {
                closeButton.setVisible(visible);
            }
        }
    }

    public class CloseListener implements MouseListener {
        private Component tab;

        public CloseListener(Component tab) {
            this.tab = tab;
        }

        @Override
        public void mouseClicked(MouseEvent e) {
            if (e.getSource() instanceof JLabel) {
                JLabel clickedButton = (JLabel) e.getSource();
                JTabbedPaneClosable tabbedPane = (JTabbedPaneClosable) clickedButton.getParent().getParent().getParent();
                clickedDelete = true;
                tabbedPane.remove(tab);
            }
        }

        @Override
        public void mousePressed(MouseEvent e) {
        }

        @Override
        public void mouseReleased(MouseEvent e) {
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            if (e.getSource() instanceof JButton) {
                JButton clickedButton = (JButton) e.getSource();
            }
        }

        @Override
        public void mouseExited(MouseEvent e) {
            if (e.getSource() instanceof JButton) {
                JButton clickedButton = (JButton) e.getSource();
            }
        }
    }
}