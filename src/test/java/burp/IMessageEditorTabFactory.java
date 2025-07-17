package burp;

public interface IMessageEditorTabFactory {
    IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable);
}