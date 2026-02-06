package burp.hv;

import burp.api.montoya.websocket.*;
import java.nio.charset.StandardCharsets;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.ui.HackvertorPanel;

/**
 * Montoya WebSocket message handler that logs processing and shows the Hackvertor panel for messages.
 */
public class HackvertorMontoyaMessageHandler implements MessageHandler {
    private final String connectionId;

    // Helper logging wrappers that are defensive: Montoya logging may be unavailable in some contexts
    private static void safeLogOutput(String msg) {
        try {
            if (HackvertorExtension.montoyaApi != null) {
                try {
                    burp.api.montoya.logging.Logging logging = HackvertorExtension.montoyaApi.logging();
                    if (logging != null) { logging.logToOutput(msg); return; }
                } catch (Throwable ignored) {}
            }
            if (HackvertorExtension.callbacks != null) {
                HackvertorExtension.callbacks.printOutput(msg);
            }
        } catch (Throwable ignored) {}
    }

    private static int countMojibakeMarkers(String s) {
        if (s == null || s.isEmpty()) return 0;
        int c = 0;
        for (int i = 0; i < s.length(); ++i) {
            char ch = s.charAt(i);
            if (ch == '\u00C3' || ch == '\u00C2') c++;
        }
        return c;
    }

    private static String tryUndoMojibake(String input) {
        if (input == null || input.isEmpty()) return input;
        try {
            String current = input;
            int prevMarkers = countMojibakeMarkers(current);
            // Try a few iterations to unroll multiple rounds of double-encoding
            for (int iter = 0; iter < 5; iter++) {
                String candidate = new String(current.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
                int candMarkers = countMojibakeMarkers(candidate);
                if (candMarkers < prevMarkers) {
                    current = candidate;
                    prevMarkers = candMarkers;
                } else {
                    break;
                }
            }
            return current;
        } catch (Exception ignored) {
            return input;
        }
    }

    private static void safeLogError(String msg) {
        try {
            if (HackvertorExtension.montoyaApi != null) {
                try {
                    burp.api.montoya.logging.Logging logging = HackvertorExtension.montoyaApi.logging();
                    if (logging != null) { logging.logToError(msg); return; }
                } catch (Throwable ignored) {}
            }
            if (HackvertorExtension.callbacks != null) {
                HackvertorExtension.callbacks.printError(msg);
            }
        } catch (Throwable ignored) {}
    }

    public HackvertorMontoyaMessageHandler() {
        this.connectionId = "unknown@0";
    }

    public HackvertorMontoyaMessageHandler(String connectionId) {
        this.connectionId = connectionId == null ? "unknown@0" : connectionId;
    }

    @Override
    public TextMessageAction handleTextMessage(TextMessage textMessage) {
        if (HackvertorExtension.hackvertor == null) {
            return TextMessageAction.continueWith(textMessage.payload());
        }
        // safeLogOutput("Hackvertor processing websocket textmessage");

        // From here on, extension is initialized — reuse existing logic for tags and logging.
        boolean tagsInWebSockets = false;
        try {
            if (HackvertorExtension.generalSettings != null) {
                tagsInWebSockets = HackvertorExtension.generalSettings.getBoolean("tagsInWebSockets");
            }
        } catch (Exception e) {
            try {
                safeLogError("Error loading settings: " + e.getMessage());
            } catch (Exception ignored) {}
            tagsInWebSockets = false;
        }

        String payload = textMessage.payload();
        String finalPayload = payload;
        boolean hadTags = payload != null && payload.contains("<@");
        boolean fixMojibake = false;
        try {
            if (HackvertorExtension.generalSettings != null) {
                fixMojibake = HackvertorExtension.generalSettings.getBoolean("fixWebsocketMojibake");
            }
        } catch (Exception ignored) {}

        if (fixMojibake) {
            payload = tryUndoMojibake(payload);
            finalPayload = payload;
        }

        if (tagsInWebSockets && hadTags) {
            String direction = "UNKNOWN";
            try {
                if (textMessage.direction() != null) {
                    direction = textMessage.direction().name();
                }
            } catch (Exception ignored) {}

            int lenBefore = payload != null ? payload.length() : 0;

            try {
                finalPayload = HackvertorExtension.hackvertor.convert(payload, HackvertorExtension.hackvertor);
            } catch (Throwable t) {
                // Log full stack to help diagnose websocket conversion issues (e.g., NPEs in tag counting)
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                String stack = sw.toString();
                String msg = "Error converting websocket payload for connection " + connectionId + ": " + t.getMessage();
                try {
                    safeLogError(msg);
                    safeLogError(stack);
                } catch (Exception ignored) {}
                finalPayload = payload;
            }

            int lenAfter = finalPayload != null ? finalPayload.length() : 0;

            if (fixMojibake) {
                finalPayload = tryUndoMojibake(finalPayload);
                lenAfter = finalPayload != null ? finalPayload.length() : 0;
            }

            // String header = "Hackvertor processed websocket text message:";
            // String details = String.format("   (direction=%s, tags=%s, id=%s, lenBefore=%d, lenAfter=%d)", direction, hadTags, connectionId, lenBefore, lenAfter);
            // try {
            //     safeLogOutput(header);
            //     safeLogOutput(details);
            // } catch (Exception ignored) {
            // }
        }

        return TextMessageAction.continueWith(finalPayload);
    }

    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
        if (HackvertorExtension.hackvertor == null) {
            return BinaryMessageAction.continueWith(binaryMessage.payload());
        }
        // safeLogOutput("Hackvertor processing websocket binarymessage");
        
        boolean tagsInWebSockets = false;
        try {
            if (HackvertorExtension.generalSettings != null) {
                tagsInWebSockets = HackvertorExtension.generalSettings.getBoolean("tagsInWebSockets");
            }
        } catch (Exception e) {
            try { safeLogError("Error loading settings: " + e.getMessage()); } catch (Exception ignored) {}
            tagsInWebSockets = false;
        }

        if (tagsInWebSockets){
            String direction = "UNKNOWN";
            try {
                if (binaryMessage.direction() != null) {
                    direction = binaryMessage.direction().name();
                }
            } catch (Exception ignored) {}

            int len = 0;
            try {
                if (binaryMessage.payload() != null) {
                    len = binaryMessage.payload().length();
                }
            } catch (Exception ignored) {}

            // String debugMsg = String.format("Hackvertor processed websocket binary message (direction=%s, len=%d)", direction, len);
            // try { safeLogOutput(debugMsg); } catch (Exception ignored) {}
        }
        return BinaryMessageAction.continueWith(binaryMessage);
    }
}
