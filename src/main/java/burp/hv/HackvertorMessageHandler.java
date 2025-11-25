package burp.hv;

import burp.api.montoya.websocket.*;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

public class HackvertorMessageHandler implements MessageHandler {

    @Override
    public TextMessageAction handleTextMessage(TextMessage textMessage) {
        boolean tagsInWebSockets;
        try {
            tagsInWebSockets = HackvertorExtension.generalSettings.getBoolean("tagsInWebSockets");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
        if(tagsInWebSockets) {
            if (textMessage.payload().contains("<@")) {
                String converted = HackvertorExtension.hackvertor.convert(textMessage.payload(), HackvertorExtension.hackvertor);
                return TextMessageAction.continueWith(converted);
            }
        }
        return TextMessageAction.continueWith(textMessage);
    }

    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
        return BinaryMessageAction.continueWith(binaryMessage);
    }
}
