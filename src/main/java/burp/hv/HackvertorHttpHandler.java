package burp.hv;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.hv.ai.AI;
import burp.hv.ai.LearnFromRepeater;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import org.json.JSONArray;

import java.util.ArrayList;

import static burp.hv.HackvertorExtension.montoyaApi;
import static burp.hv.HackvertorExtension.requestHistory;

public class HackvertorHttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        boolean learnFromRepeater;
        boolean allowAiToGenerateCode;
        boolean tagsInProxy;
        boolean tagsInIntruder;
        boolean tagsInRepeater;
        boolean tagsInScanner;
        boolean tagsInExtensions;
        boolean autoUpdateContentLength;
        int maxBodyLength;
        try {
            learnFromRepeater = HackvertorExtension.generalSettings.getBoolean("learnFromRepeater");
            allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            tagsInProxy = HackvertorExtension.generalSettings.getBoolean("tagsInProxy");
            tagsInIntruder = HackvertorExtension.generalSettings.getBoolean("tagsInIntruder");
            tagsInRepeater = HackvertorExtension.generalSettings.getBoolean("tagsInRepeater");
            tagsInScanner = HackvertorExtension.generalSettings.getBoolean("tagsInScanner");
            tagsInExtensions = HackvertorExtension.generalSettings.getBoolean("tagsInExtensions");
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

        switch (req.toolSource().toolType()) {
            case PROXY:
                if (!tagsInProxy) {
                    return null;
                }
                break;
            case INTRUDER:
                if (!tagsInIntruder) {
                    return null;
                }
                break;
            case REPEATER:
                if (!tagsInRepeater) {
                    return null;
                }
                break;
            case SCANNER:
                if (!tagsInScanner) {
                    return null;
                }
                break;
            case EXTENSIONS:
                if (!tagsInExtensions) {
                    return null;
                }
                break;
            default:
                return null;
        }
        String requestStr = req.toString();
        if (requestStr.contains("<@")) {
            HackvertorExtension.hackvertor.setRequest(req);
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
                convertedReq.withUpdatedHeader("Content-Length", convertedReq.body().length()+"");
            }
            return RequestToBeSentAction.continueWith(convertedReq);
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return null;
    }
}
