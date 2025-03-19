package burp.hv.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.hv.HackvertorExtension;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MontoyaContextMenu implements ContextMenuItemsProvider {
    private final MontoyaApi api;

    public MontoyaContextMenu(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        boolean tagsInProxy;
        try {
            tagsInProxy = HackvertorExtension.generalSettings.getBoolean("tagsInProxy");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
        if (event.isFromTool(ToolType.PROXY) && !tagsInProxy) {
            List<Component> menuItemList = new ArrayList<>();
            JMenuItem tagsInProxyItem = new JMenuItem("Tags in the proxy are disabled");
            tagsInProxyItem.addActionListener(e -> HackvertorExtension.alert("You can enable them in Hackvertor->Settings->Allow tags in proxy"));
            menuItemList.add(tagsInProxyItem);
            return menuItemList;
        }

        return null;
    }
}
