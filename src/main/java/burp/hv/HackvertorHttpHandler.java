package burp.hv;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.hv.ai.AI;
import burp.hv.ai.LearnFromRepeater;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.TagAutomator;
import burp.hv.utils.ExecutionKeyRedactor;
import burp.hv.utils.TagUtils;
import org.json.JSONArray;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import static burp.hv.HackvertorExtension.montoyaApi;
import static burp.hv.HackvertorExtension.requestHistory;

public class HackvertorHttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    private static final Object requestHistoryLock = new Object();

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            return processRequest(req);
        } catch (Throwable t) {
            // Never let an unconverted request (which may contain the tag execution key) escape on failure
            montoyaApi.logging().logToError("Hackvertor failed to process request: " + t);
            return redactIfNeeded(req);
        }
    }

    private RequestToBeSentAction processRequest(HttpRequestToBeSent req) {
        boolean learnFromRepeater;
        boolean allowAiToGenerateCode;
        boolean autoUpdateContentLength;
        int maxBodyLength;
        try {
            learnFromRepeater = HackvertorExtension.generalSettings.getBoolean("learnFromRepeater");
            allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            autoUpdateContentLength = HackvertorExtension.generalSettings.getBoolean("autoUpdateContentLength");
            maxBodyLength = HackvertorExtension.generalSettings.getInteger("maxBodyLength");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }

        if(learnFromRepeater && AI.isAiSupported() && req.toolSource().isFromTool(ToolType.REPEATER)) {
            recordRepeaterRequest(req, allowAiToGenerateCode);
        }
        if(!TagUtils.shouldProcessTags(req.toolSource().toolType())) return redactIfNeeded(req);

        String requestStr = new String(req.toByteArray().getBytes(), StandardCharsets.UTF_8);
        String tool = getToolFromToolType(req.toolSource().toolType());
        boolean hasTagAutomatorRules = TagAutomator.shouldApplyRules("request", tool, "HTTP");
        if (requestStr.contains("<@") || hasTagAutomatorRules) {
            HackvertorExtension.hackvertor.setRequest(req);
            final String finalRequestStr = requestStr;
            if(hasTagAutomatorRules) {
                try {
                    requestStr = HackvertorExtension.executorService.submit(() -> TagAutomator.applyRules(finalRequestStr, "request", tool, "HTTP")).get();
                } catch (Exception ignored) {}
            }

            HttpRequest convertedReq;
            if(req.body().length() > maxBodyLength) {
                montoyaApi.logging().logToOutput("Warning: Hackvertor only converted tags in headers because the body was too big. Hit the "+maxBodyLength + " limit.");
                // Split the string being converted (which TagAutomator may have changed) rather than using the
                // original request's byte offset, and keep the original body bytes untouched
                String headers = requestStr.substring(0, headersEnd(requestStr));
                String convertedHeaders = HackvertorExtension.hackvertor.convert(headers, HackvertorExtension.hackvertor);
                convertedReq = HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(convertedHeaders).withAppended(req.body()));
            } else {
                convertedReq = HttpRequest.httpRequest(req.httpService(), HackvertorExtension.hackvertor.convert(requestStr, HackvertorExtension.hackvertor));
            }
            if (autoUpdateContentLength) {
                convertedReq = convertedReq.withUpdatedHeader("Content-Length", convertedReq.body().length()+"");
            }
            HttpRequest redactedReq = redactRequest(convertedReq);
            if (redactedReq != convertedReq) logRedaction(req);
            return RequestToBeSentAction.continueWith(redactedReq, req.annotations());
        }
        return redactIfNeeded(req);
    }

    private static void recordRepeaterRequest(HttpRequestToBeSent req, boolean allowAiToGenerateCode) {
        int maxRequestHistory = 5;
        HttpRequest historyEntry = redactRequest(req);
        JSONArray headersAndParameters = null;
        synchronized (requestHistoryLock) {
            HackvertorExtension.requestHistoryPos++;
            if(HackvertorExtension.requestHistoryPos >= maxRequestHistory) {
                HackvertorExtension.requestHistoryPos = 0;
                headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new HttpRequest[0]));
                HackvertorExtension.requestHistory = new ArrayList<>();
            } else {
                HackvertorExtension.requestHistory.add(historyEntry);
            }
        }
        if (headersAndParameters != null) {
            LearnFromRepeater.learn(headersAndParameters, allowAiToGenerateCode);
        }
    }

    static int headersEnd(String request) {
        int end = request.indexOf("\r\n\r\n");
        if (end != -1) return end + 4;
        end = request.indexOf("\n\n");
        if (end != -1) return end + 2;
        return request.length();
    }

    private static RequestToBeSentAction redactIfNeeded(HttpRequestToBeSent req) {
        HttpRequest redacted = redactRequest(req);
        if (redacted == req) return null;
        logRedaction(req);
        return RequestToBeSentAction.continueWith(redacted, req.annotations());
    }

    private static HttpRequest redactRequest(HttpRequest req) {
        if (!ExecutionKeyRedactor.isKeyInUse()) return req;
        ByteArray bytes = req.toByteArray();
        if (!ExecutionKeyRedactor.containsKey(ExecutionKeyRedactor.ByteSource.of(bytes))) return req;
        return HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(ExecutionKeyRedactor.redact(bytes.getBytes())));
    }

    private static void logRedaction(HttpRequestToBeSent req) {
        String toolName = req.toolSource().toolType().toolName();
        if (!ExecutionKeyRedactor.shouldLogRedaction(toolName)) return;
        montoyaApi.logging().logToError("Hackvertor redacted the tag execution key from a " + toolName
                + " request to " + req.httpService().host() + ". The tags were probably not converted, e.g. because they were mutated by Burp Scanner or tags are disabled for this tool."
                + " Further redactions from " + toolName + " will not be logged.");
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        try {
            boolean tagsInResponse = HackvertorExtension.generalSettings.getBoolean("tagsInResponse");
            int maxBodyLength = HackvertorExtension.generalSettings.getInteger("maxBodyLength");
            if(!tagsInResponse) {
                return null;
            }
            String tool = getToolFromToolType(resp.toolSource().toolType());
            if(!TagAutomator.shouldApplyRules("response", tool, "HTTP")) return null;
            if(!TagUtils.shouldProcessTags(resp.toolSource().toolType())) return null;
            if(resp.body().length() > maxBodyLength) return null;
            HackvertorExtension.hackvertor.setRequest(resp.initiatingRequest());
            HackvertorExtension.hackvertor.setResponse(resp);
            String responseStr = new String(resp.toByteArray().getBytes(), StandardCharsets.UTF_8);
            final String finalResponseStr = responseStr;
            try {
                responseStr = HackvertorExtension.executorService.submit(() -> TagAutomator.applyRules(finalResponseStr, "response", tool, "HTTP")).get();
            } catch (Exception ignored) {}
            String converted = ExecutionKeyRedactor.redact(HackvertorExtension.hackvertor.convert(responseStr, HackvertorExtension.hackvertor));
            return ResponseReceivedAction.continueWith(HttpResponse.httpResponse(converted));
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
    }

    private String getToolFromToolType(ToolType toolType) {
        switch(toolType) {
            case PROXY:
                return "Proxy";
            case INTRUDER:
                return "Intruder";
            case REPEATER:
                return "Repeater";
            case SCANNER:
                return "Scanner";
            case EXTENSIONS:
                return "Extensions";
            default:
                return "Repeater";
        }
    }
}
