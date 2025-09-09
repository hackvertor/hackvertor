package burp.hv;

import burp.IContextMenuInvocation;
import burp.IResponseInfo;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.hv.ui.ExtensionPanel;
import burp.hv.ui.HackvertorPanel;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

public class HackvertorAction extends AbstractAction {

    private final ExtensionPanel extensionPanel;
    private final ContextMenuEvent event;
    private static final long serialVersionUID = 1L;

    public HackvertorAction(String text, ExtensionPanel extensionPanel, ContextMenuEvent event) {
        super(text);
        this.extensionPanel = extensionPanel;
        this.event = event;
    }

    public void actionPerformed(ActionEvent e) {
        String message = null;
        String body = null;
        switch (event.invocationType()) {
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_VIEWER_REQUEST:
                //Intruder Context menu doesn't have the requestEditor unfortunately
                //case INTRUDER_PAYLOAD_POSITIONS:
                message = event.messageEditorRequestResponse().get().requestResponse().request().toString();
                body = event.messageEditorRequestResponse().get().requestResponse().request().bodyToString();
                break;
            case MESSAGE_VIEWER_RESPONSE:
                message = event.messageEditorRequestResponse().get().requestResponse().response().toString();
                body = event.messageEditorRequestResponse().get().requestResponse().response().bodyToString();
                break;
        }
        if (message != null) {
            HackvertorPanel hackvertorPanel = extensionPanel.addNewPanel();
            Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
            int start = editor.get().caretPosition();
            int end = editor.get().caretPosition();
            if(editor.get().selectionOffsets().isPresent()) {
                start = editor.get().selectionOffsets().get().startIndexInclusive();
                end = editor.get().selectionOffsets().get().endIndexExclusive();
            }
            if (start == end) {
                if(!body.isEmpty()) {
                    hackvertorPanel.getInputArea().setText(body);
                } else {
                    hackvertorPanel.getInputArea().setText(message);
                }
            } else {
                hackvertorPanel.getInputArea().setText("<@auto_decode_no_decrypt>" + message.substring(start, end).trim() + "</@auto_decode_no_decrypt>");
            }
            extensionPanel.makeActiveBurpTab();
        }
    }

}
