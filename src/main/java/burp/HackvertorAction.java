package burp;

import burp.ui.ExtensionPanel;
import burp.ui.HackvertorPanel;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class HackvertorAction extends AbstractAction {

    private final ExtensionPanel extensionPanel;
    private final IContextMenuInvocation invocation;
    private static final long serialVersionUID = 1L;

    HackvertorAction(String text, ExtensionPanel extensionPanel, IContextMenuInvocation invocation) {
        super(text);
        this.extensionPanel = extensionPanel;
        this.invocation = invocation;
    }

    public void actionPerformed(ActionEvent e) {
        byte[] message = null;
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
                message = invocation.getSelectedMessages()[0].getRequest();
                break;
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                message = invocation.getSelectedMessages()[0].getResponse();
                break;
        }
        int[] bounds = invocation.getSelectionBounds();
        if (message != null) {
            HackvertorPanel hackvertorPanel = extensionPanel.addNewPanel();
            if (bounds[0] == bounds[1]) {
                IResponseInfo analyzedResponse = BurpExtender.helpers.analyzeResponse(message);
                message = Arrays.copyOfRange(message, analyzedResponse.getBodyOffset(), message.length);
                //TODO Create and use new hackvertor tag for context menu actions
                hackvertorPanel.getInputArea().setText(new String(message, StandardCharsets.ISO_8859_1));
            } else {
                hackvertorPanel.getInputArea().setText("<@auto_decode_no_decrypt>" + new String(Arrays.copyOfRange(message, bounds[0], bounds[1]), StandardCharsets.ISO_8859_1).trim() + "<@/auto_decode_no_decrypt>");
            }
            extensionPanel.makeActiveBurpTab();
        }
    }

}
