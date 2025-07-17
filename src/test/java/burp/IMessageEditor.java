package burp;

import java.awt.Component;

public interface IMessageEditor {
    Component getComponent();
    void setMessage(byte[] message, boolean isRequest);
    byte[] getMessage();
    boolean isMessageModified();
    byte[] getSelectedData();
    int[] getSelectionBounds();
}