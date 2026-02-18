package burp.hv;

import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

public class HackvertorWebSocketHandler implements WebSocketCreatedHandler {

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        webSocketCreated.webSocket().registerMessageHandler(new HackvertorMontoyaMessageHandler());
    }
}
