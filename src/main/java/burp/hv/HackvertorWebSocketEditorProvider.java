package burp.hv;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.hv.ui.HackvertorPanel;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

/**
 * Montoya WebSocket message editor provider that embeds the Hackvertor panel as a tab in the WebSockets viewer.
 */
public class HackvertorWebSocketEditorProvider implements WebSocketMessageEditorProvider {

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorCreationContext) {
        return new ExtensionProvidedWebSocketMessageEditor() {
            private final JPanel container = new JPanel(new BorderLayout());
            private HackvertorPanel hackvertorPanel = null;
            private WebSocketMessage currentMessage = null;
            private boolean interfaceCreated = false;
            private boolean changed = false;

            private void ensureInterfaceCreated() {
                if (interfaceCreated) return;
                SwingUtilities.invokeLater(() -> {
                    boolean shouldShowOutput = false;
                    try {
                        shouldShowOutput = HackvertorExtension.generalSettings.getBoolean("showOutputInMessageEditor");
                    } catch (Exception ignored) {
                    }
                    hackvertorPanel = new HackvertorPanel(HackvertorExtension.hackvertor, false, !shouldShowOutput, true);
                    hackvertorPanel.getInputArea().getDocument().addDocumentListener(new DocumentListener() {
                        @Override
                        public void insertUpdate(DocumentEvent e) { changed = true; }

                        @Override
                        public void removeUpdate(DocumentEvent e) { changed = true; }

                        @Override
                        public void changedUpdate(DocumentEvent e) { changed = true; }
                    });
                    container.add(hackvertorPanel, BorderLayout.CENTER);
                    if (currentMessage != null) {
                        try {
                            String text = currentMessage.payload().toString();
                            hackvertorPanel.getInputArea().setText(text);
                        } catch (Exception ignored) {
                        }
                    }
                    interfaceCreated = true;
                });
            }

            @Override
            public ByteArray getMessage() {
                if (changed && hackvertorPanel != null) {
                    String txt = hackvertorPanel.getInputArea().getText();
                    return ByteArray.byteArray(txt);
                }
                if (currentMessage != null) {
                    return currentMessage.payload();
                }
                return ByteArray.byteArray("");
            }

            @Override
            public void setMessage(WebSocketMessage webSocketMessage) {
                this.currentMessage = webSocketMessage;
                ensureInterfaceCreated();
                if (hackvertorPanel != null && webSocketMessage != null) {
                    try {
                        String text = webSocketMessage.payload().toString();
                        hackvertorPanel.getInputArea().setText(text);
                        changed = false;
                    } catch (Exception ignored) {
                    }
                }
            }

            @Override
            public boolean isEnabledFor(WebSocketMessage webSocketMessage) {
                return true;
            }

            @Override
            public String caption() {
                return "Hackvertor";
            }

            @Override
            public Component uiComponent() {
                ensureInterfaceCreated();
                return container;
            }

            @Override
            public Selection selectedData() {
                if (hackvertorPanel == null) {
                    return Selection.selection(ByteArray.byteArray(""));
                }
                String sel = hackvertorPanel.getInputArea().getSelectedText();
                if (sel == null) {
                    return Selection.selection(ByteArray.byteArray(""));
                }
                return Selection.selection(ByteArray.byteArray(sel));
            }

            @Override
            public boolean isModified() {
                return changed;
            }
        };
    }
}
