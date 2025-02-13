package burp.hv;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.hv.ai.AI;
import burp.hv.ai.CodeConversion;
import burp.hv.ai.LearnFromRepeater;
import burp.hv.ai.PromptGenerator;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.CustomTags;
import burp.hv.utils.HttpUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import static burp.hv.HackvertorExtension.montoyaApi;
import static burp.hv.HackvertorExtension.requestHistory;

public class HttpListener implements IHttpListener {

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }

        boolean learnFromRepeater;
        boolean debugAi;
        boolean allowAiToGenerateCode;
        boolean tagsInProxy;
        boolean tagsInIntruder;
        boolean tagsInRepeater;
        boolean tagsInScanner;
        boolean tagsInExtensions;
        boolean autoUpdateContentLength;
        try {
            learnFromRepeater = HackvertorExtension.generalSettings.getBoolean("learnFromRepeater");
            debugAi = HackvertorExtension.generalSettings.getBoolean("debugAi");
            allowAiToGenerateCode = HackvertorExtension.generalSettings.getBoolean("allowAiToGenerateCode");
            tagsInProxy = HackvertorExtension.generalSettings.getBoolean("tagsInProxy");
            tagsInIntruder = HackvertorExtension.generalSettings.getBoolean("tagsInIntruder");
            tagsInRepeater = HackvertorExtension.generalSettings.getBoolean("tagsInRepeater");
            tagsInScanner = HackvertorExtension.generalSettings.getBoolean("tagsInScanner");
            tagsInExtensions = HackvertorExtension.generalSettings.getBoolean("tagsInExtensions");
            autoUpdateContentLength = HackvertorExtension.generalSettings.getBoolean("autoUpdateContentLength");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            HackvertorExtension.callbacks.printError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }

        if(learnFromRepeater && AI.isAiSupported() && toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            HackvertorExtension.requestHistoryPos++;
            int maxRequestHistory = 5;
            if(HackvertorExtension.requestHistoryPos >= maxRequestHistory) {
                HackvertorExtension.requestHistoryPos = 0;
                JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.toArray(new IRequestInfo[0]));
                HackvertorExtension.requestHistory = new ArrayList<>();
                LearnFromRepeater.learn(headersAndParameters, allowAiToGenerateCode);
            } else {
                IRequestInfo currentRequest = HackvertorExtension.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                HackvertorExtension.requestHistory.add(currentRequest);
            }
        }

        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                if (!tagsInProxy) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                if (!tagsInIntruder) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                if (!tagsInRepeater) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                if (!tagsInScanner) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                if (!tagsInExtensions) {
                    return;
                }
                break;
            default:
                return;
        }
        byte[] request = messageInfo.getRequest();
        if (HackvertorExtension.helpers.indexOf(request, HackvertorExtension.helpers.stringToBytes("<@"), false, 0, request.length) > -1) {
            String requestStr = HackvertorExtension.helpers.bytesToString(request);
            HackvertorExtension.hackvertor.analyzeRequest(HackvertorExtension.helpers.stringToBytes(Hackvertor.removeHackvertorTags(requestStr)), messageInfo);
            request = HackvertorExtension.helpers.stringToBytes(HackvertorExtension.hackvertor.convert(requestStr, HackvertorExtension.hackvertor));
            if (autoUpdateContentLength) {
                request = HttpUtils.fixContentLength(request);
            }
            messageInfo.setRequest(request);
        }
    }
}
