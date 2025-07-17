package burp;

import java.awt.Component;

public interface IMessageEditorTab {
    String getTabCaption();
    Component getUiComponent();
    boolean isEnabled(byte[] content, boolean isRequest);
    void setMessage(byte[] content, boolean isRequest);
    byte[] getMessage();
    boolean isModified();
    byte[] getSelectedData();
}