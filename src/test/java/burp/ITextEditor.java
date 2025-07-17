package burp;

import java.awt.Component;

public interface ITextEditor {
    Component getComponent();
    void setText(byte[] text);
    byte[] getText();
    boolean isTextModified();
    byte[] getSelectedText();
    int[] getSelectionBounds();
    void setSearchExpression(String expression);
}