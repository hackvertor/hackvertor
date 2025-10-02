package burp.hv;

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
import burp.hv.utils.TagUtils;
import org.json.JSONArray;

import java.util.ArrayList;

import static burp.hv.HackvertorExtension.montoyaApi;
import static burp.hv.HackvertorExtension.requestHistory;

public class HackvertorHttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
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
                HackvertorExtension.requestHistory.add(req);
            }
        }
        if(!TagUtils.shouldProcessTags(req.toolSource().toolType())) return null;

        String requestStr = req.toString();
        if (requestStr.contains("<@")) {
            HackvertorExtension.hackvertor.setRequest(req);

            String tool = getToolFromToolType(req.toolSource().toolType());
            final String finalRequestStr = requestStr;
            if(TagAutomator.shouldApplyRules("request", tool, "HTTP")) {
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
            HttpRequest convertedReq = HttpRequest.httpRequest(req.httpService(), converted);
            if (autoUpdateContentLength) {
                convertedReq = convertedReq.withUpdatedHeader("Content-Length", convertedReq.body().length()+"");
            }
            return RequestToBeSentAction.continueWith(convertedReq);
        }
        return null;
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
            String responseStr = resp.toString();
            final String finalResponseStr = responseStr;
            try {
                responseStr = HackvertorExtension.executorService.submit(() -> TagAutomator.applyRules(finalResponseStr, "response", tool, "HTTP")).get();
            } catch (Exception ignored) {}
            return ResponseReceivedAction.continueWith(HttpResponse.httpResponse(HackvertorExtension.hackvertor.convert(responseStr, HackvertorExtension.hackvertor)));
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
