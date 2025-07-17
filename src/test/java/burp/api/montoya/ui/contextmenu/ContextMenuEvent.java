package burp.api.montoya.ui.contextmenu;

public interface ContextMenuEvent {
    boolean isFromTool();
    MessageEditorHttpRequestResponse messageEditorRequestResponse();
}