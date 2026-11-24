package burp.hv;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.websocket.*;
import java.nio.charset.StandardCharsets;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.ui.HackvertorPanel;
import burp.hv.utils.ExecutionKeyRedactor;

/**
 * Montoya WebSocket message handler that logs processing and shows the Hackvertor panel for messages.
 */
public class HackvertorMontoyaMessageHandler implements MessageHandler {

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
    }

    @Override
    public TextMessageAction handleTextMessage(TextMessage textMessage) {
        if (HackvertorExtension.hackvertor == null) {
            return TextMessageAction.continueWith(redactText(textMessage.payload()));
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
                String msg = "Error converting websocket payload: " + t.getMessage();
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
            // String details = String.format("   (direction=%s, tags=%s, lenBefore=%d, lenAfter=%d)", direction, hadTags, lenBefore, lenAfter);
            // try {
            //     safeLogOutput(header);
            //     safeLogOutput(details);
            // } catch (Exception ignored) {
            // }
        }

        return TextMessageAction.continueWith(redactText(finalPayload));
    }

    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
        if (HackvertorExtension.hackvertor == null) {
            return BinaryMessageAction.continueWith(redactBinary(binaryMessage.payload()));
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
        return BinaryMessageAction.continueWith(redactBinary(binaryMessage.payload()));
    }

    // Tags that failed to convert (or weren't converted because tags are disabled) would leak the tag execution key
    private static String redactText(String payload) {
        if (!ExecutionKeyRedactor.containsKey(payload)) return payload;
        logRedaction();
        return ExecutionKeyRedactor.redact(payload);
    }

    private static ByteArray redactBinary(ByteArray payload) {
        if (payload == null || !ExecutionKeyRedactor.containsKey(ExecutionKeyRedactor.ByteSource.of(payload))) return payload;
        logRedaction();
        return ByteArray.byteArray(ExecutionKeyRedactor.redact(payload.getBytes()));
    }

    private static void logRedaction() {
        if (!ExecutionKeyRedactor.shouldLogRedaction("WebSockets")) return;
        safeLogError("Hackvertor redacted the tag execution key from a WebSocket message. The tags were probably not converted."
                + " Further redactions from WebSockets will not be logged.");
    }
}
