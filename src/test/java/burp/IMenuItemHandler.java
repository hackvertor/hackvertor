package burp;

import javax.swing.JMenuItem;

public interface IMenuItemHandler {
    void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo);
}