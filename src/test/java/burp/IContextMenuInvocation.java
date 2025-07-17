package burp;

import java.awt.event.InputEvent;

public interface IContextMenuInvocation {
    byte getToolFlag();
    byte getInvocationContext();
    String getSelectedText();
    int[] getSelectionBounds();
    IHttpRequestResponse[] getSelectedMessages();
    InputEvent getInputEvent();
}