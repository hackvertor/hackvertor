package burp;

import java.util.List;

public interface IContextMenuFactory {
    List<javax.swing.JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}