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
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            return processRequest(req);
        } catch (RuntimeException e) {
            // Never let an unconverted request (which may contain the tag execution key) escape on failure
            montoyaApi.logging().logToError("Hackvertor failed to process request: " + e);
            return RequestToBeSentAction.continueWith(redactRequest(req));
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
            HackvertorExtension.requestHistoryPos++;
            int maxRequestHistory = 5;
            if(HackvertorExtension.requestHistoryPos >= maxRequestHistory) {
                HackvertorExtension.requestHistoryPos = 0;
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new HttpRequest[0]));
                HackvertorExtension.requestHistory = new ArrayList<>();
                LearnFromRepeater.learn(headersAndParameters, allowAiToGenerateCode);
            } else {
                HackvertorExtension.requestHistory.add(redactRequest(req));
            }
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

            String converted;
            if(req.body().length() > maxBodyLength) {
                montoyaApi.logging().logToOutput("Warning: Hackvertor only converted tags in headers because the body was too big. Hit the "+maxBodyLength + " limit.");
                String headers = requestStr.substring(0, req.bodyOffset());
                String convertedHeaders = HackvertorExtension.hackvertor.convert(headers, HackvertorExtension.hackvertor);
                converted = convertedHeaders + req.bodyToString();
            } else {
                converted = HackvertorExtension.hackvertor.convert(requestStr, HackvertorExtension.hackvertor);
            }
            if (ExecutionKeyRedactor.containsKey(converted)) {
                logRedaction(req);
                converted = ExecutionKeyRedactor.redact(converted);
            }
            HttpRequest convertedReq = HttpRequest.httpRequest(req.httpService(), converted);
            if (autoUpdateContentLength) {
                convertedReq = convertedReq.withUpdatedHeader("Content-Length", convertedReq.body().length()+"");
            }
            return RequestToBeSentAction.continueWith(convertedReq);
        }
        return redactIfNeeded(req);
    }

    private static RequestToBeSentAction redactIfNeeded(HttpRequestToBeSent req) {
        HttpRequest redacted = redactRequest(req);
        if (redacted == req) return null;
        logRedaction(req);
        return RequestToBeSentAction.continueWith(redacted);
    }

    private static HttpRequest redactRequest(HttpRequest req) {
        byte[] bytes = req.toByteArray().getBytes();
        if (!ExecutionKeyRedactor.containsKey(bytes)) return req;
        return HttpRequest.httpRequest(req.httpService(), ByteArray.byteArray(ExecutionKeyRedactor.redact(bytes)));
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
