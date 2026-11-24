package burp.hv;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.websocket.*;
import burp.hv.utils.ExecutionKeyRedactor;
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
                return TextMessageAction.continueWith(ExecutionKeyRedactor.redact(converted));
            }
        }
        return TextMessageAction.continueWith(ExecutionKeyRedactor.redact(textMessage.payload()));
    }

    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
        byte[] bytes = binaryMessage.payload().getBytes();
        if (!ExecutionKeyRedactor.containsKey(bytes)) return BinaryMessageAction.continueWith(binaryMessage);
        return BinaryMessageAction.continueWith(ByteArray.byteArray(ExecutionKeyRedactor.redact(bytes)));
    }
}
