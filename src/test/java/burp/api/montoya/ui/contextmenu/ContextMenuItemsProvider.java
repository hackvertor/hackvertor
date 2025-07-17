package burp.api.montoya.ui.contextmenu;

import java.util.List;

public interface ContextMenuItemsProvider {
    List<ContextMenuItem> provideMenuItems(ContextMenuEvent event);
}