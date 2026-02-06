package burp.hv;

import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;
import burp.api.montoya.http.message.requests.HttpRequest;

public class HackvertorWebSocketHandler implements WebSocketCreatedHandler {

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        // Derive a connection id from the upgrade request when available, or fall back to identityHashCode.
        String connectionId = "unknown@0";
        try {
            HttpRequest upgrade = webSocketCreated.upgradeRequest();
            if (upgrade != null && upgrade.httpService() != null) {
                connectionId = String.format("%s@%d#%d", upgrade.httpService().host(), upgrade.httpService().port(), System.identityHashCode(webSocketCreated.webSocket()));
            } else {
                connectionId = "ws@" + System.identityHashCode(webSocketCreated.webSocket());
            }
        } catch (Exception ignored) {}

        webSocketCreated.webSocket().registerMessageHandler(new HackvertorMontoyaMessageHandler(connectionId));
    }
}
