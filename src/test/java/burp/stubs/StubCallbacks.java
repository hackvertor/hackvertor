package burp.stubs;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class StubCallbacks implements IBurpExtenderCallbacks {

    private JFrame frame;

    public StubCallbacks(JFrame frame){
        this.frame = frame;
    }

    @Override
    public void setExtensionName(String s) {

    }

    @Override
    public IExtensionHelpers getHelpers() {
        return new IExtensionHelpers() {
            @Override
            public IRequestInfo analyzeRequest(IHttpRequestResponse iHttpRequestResponse) {
                return null;
            }

            @Override
            public IRequestInfo analyzeRequest(IHttpService iHttpService, byte[] bytes) {
                return null;
            }

            @Override
            public IRequestInfo analyzeRequest(byte[] bytes) {
                return null;
            }

            @Override
            public IResponseInfo analyzeResponse(byte[] bytes) {
                return null;
            }

            @Override
            public IParameter getRequestParameter(byte[] bytes, String s) {
                return null;
            }

            @Override
            public String urlDecode(String s) {
                try {
                    return URLDecoder.decode(s, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                    return "";
                }
            }

            @Override
            public String urlEncode(String s) {
                try {
                    return URLEncoder.encode(s, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                    return "";
                }
            }

            @Override
            public byte[] urlDecode(byte[] bytes) {
                return URLDecoder.decode(new String(bytes)).getBytes();
            }

            @Override
            public byte[] urlEncode(byte[] bytes) {
                return new byte[0];
            }

            @Override
            public byte[] base64Decode(String s) {
                return Base64.getDecoder().decode(s);
            }

            @Override
            public byte[] base64Decode(byte[] bytes) {
                return Base64.getDecoder().decode(bytes);
            }

            @Override
            public String base64Encode(String s) {
                return Base64.getEncoder().encodeToString(s.getBytes());
            }

            @Override
            public String base64Encode(byte[] bytes) {
                return Base64.getEncoder().encodeToString(bytes);
            }

            @Override
            public byte[] stringToBytes(String s) {
                return s.getBytes();
            }

            @Override
            public String bytesToString(byte[] bytes) {
                return new String(bytes, Charset.defaultCharset());
            }

            @Override
            public int indexOf(byte[] bytes, byte[] bytes1, boolean b, int i, int i1) {
                return 0;
            }

            @Override
            public byte[] buildHttpMessage(List<String> list, byte[] bytes) {
                return new byte[0];
            }

            @Override
            public byte[] buildHttpRequest(URL url) {
                return new byte[0];
            }

            @Override
            public byte[] addParameter(byte[] bytes, IParameter iParameter) {
                return new byte[0];
            }

            @Override
            public byte[] removeParameter(byte[] bytes, IParameter iParameter) {
                return new byte[0];
            }

            @Override
            public byte[] updateParameter(byte[] bytes, IParameter iParameter) {
                return new byte[0];
            }

            @Override
            public byte[] toggleRequestMethod(byte[] bytes) {
                return new byte[0];
            }

            @Override
            public IHttpService buildHttpService(String s, int i, String s1) {
                return null;
            }

            @Override
            public IHttpService buildHttpService(String s, int i, boolean b) {
                return null;
            }

            @Override
            public IParameter buildParameter(String s, String s1, byte b) {
                return null;
            }

            @Override
            public IScannerInsertionPoint makeScannerInsertionPoint(String s, byte[] bytes, int i, int i1) {
                return null;
            }

            @Override
            public IResponseVariations analyzeResponseVariations(byte[]... bytes) {
                return null;
            }

            @Override
            public IResponseKeywords analyzeResponseKeywords(List<String> list, byte[]... bytes) {
                return null;
            }
        };
    }

    @Override
    public OutputStream getStdout() {
        return System.out;
    }

    @Override
    public OutputStream getStderr() {
        return System.err;
    }

    @Override
    public void printOutput(String s) {
        System.out.println(s);
    }

    @Override
    public void printError(String s) {
        System.err.println(s);
    }

    @Override
    public void registerExtensionStateListener(IExtensionStateListener iExtensionStateListener) {

    }

    @Override
    public List<IExtensionStateListener> getExtensionStateListeners() {
        return null;
    }

    @Override
    public void removeExtensionStateListener(IExtensionStateListener iExtensionStateListener) {

    }

    @Override
    public void registerHttpListener(IHttpListener iHttpListener) {

    }

    @Override
    public List<IHttpListener> getHttpListeners() {
        return null;
    }

    @Override
    public void removeHttpListener(IHttpListener iHttpListener) {

    }

    @Override
    public void registerProxyListener(IProxyListener iProxyListener) {

    }

    @Override
    public List<IProxyListener> getProxyListeners() {
        return null;
    }

    @Override
    public void removeProxyListener(IProxyListener iProxyListener) {

    }

    @Override
    public void registerScannerListener(IScannerListener iScannerListener) {

    }

    @Override
    public List<IScannerListener> getScannerListeners() {
        return null;
    }

    @Override
    public void removeScannerListener(IScannerListener iScannerListener) {

    }

    @Override
    public void registerScopeChangeListener(IScopeChangeListener iScopeChangeListener) {

    }

    @Override
    public List<IScopeChangeListener> getScopeChangeListeners() {
        return null;
    }

    @Override
    public void removeScopeChangeListener(IScopeChangeListener iScopeChangeListener) {

    }

    @Override
    public void registerContextMenuFactory(IContextMenuFactory iContextMenuFactory) {

    }

    @Override
    public List<IContextMenuFactory> getContextMenuFactories() {
        return null;
    }

    @Override
    public void removeContextMenuFactory(IContextMenuFactory iContextMenuFactory) {

    }

    @Override
    public void registerMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {

    }

    @Override
    public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
        return null;
    }

    @Override
    public void removeMessageEditorTabFactory(IMessageEditorTabFactory iMessageEditorTabFactory) {

    }

    @Override
    public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {

    }

    @Override
    public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
        return null;
    }

    @Override
    public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider iScannerInsertionPointProvider) {

    }

    @Override
    public void registerScannerCheck(IScannerCheck iScannerCheck) {

    }

    @Override
    public List<IScannerCheck> getScannerChecks() {
        return null;
    }

    @Override
    public void removeScannerCheck(IScannerCheck iScannerCheck) {

    }

    @Override
    public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {

    }

    @Override
    public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
        return null;
    }

    @Override
    public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory iIntruderPayloadGeneratorFactory) {

    }

    @Override
    public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {

    }

    @Override
    public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
        return null;
    }

    @Override
    public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor iIntruderPayloadProcessor) {

    }

    @Override
    public void registerSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {

    }

    @Override
    public List<ISessionHandlingAction> getSessionHandlingActions() {
        return null;
    }

    @Override
    public void removeSessionHandlingAction(ISessionHandlingAction iSessionHandlingAction) {

    }

    @Override
    public void unloadExtension() {

    }

    @Override
    public void addSuiteTab(ITab iTab) {
        frame.getContentPane().add(iTab.getUiComponent(), BorderLayout.CENTER);
        frame.pack();
    }

    @Override
    public void removeSuiteTab(ITab iTab) {

    }

    @Override
    public void customizeUiComponent(Component component) {

    }

    @Override
    public IMessageEditor createMessageEditor(IMessageEditorController iMessageEditorController, boolean b) {
        return null;
    }

    @Override
    public String[] getCommandLineArguments() {
        return new String[0];
    }

    @Override
    public void saveExtensionSetting(String s, String s1) {

    }

    @Override
    public String loadExtensionSetting(String s) {
        return null;
    }

    @Override
    public ITextEditor createTextEditor() {
        return null;
    }

    @Override
    public void sendToRepeater(String s, int i, boolean b, byte[] bytes, String s1) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes) {

    }

    @Override
    public void sendToIntruder(String s, int i, boolean b, byte[] bytes, List<int[]> list) {

    }

    @Override
    public void sendToComparer(byte[] bytes) {

    }

    @Override
    public void sendToSpider(URL url) {

    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes) {
        return null;
    }

    @Override
    public IScanQueueItem doActiveScan(String s, int i, boolean b, byte[] bytes, List<int[]> list) {
        return null;
    }

    @Override
    public void doPassiveScan(String s, int i, boolean b, byte[] bytes, byte[] bytes1) {

    }

    @Override
    public IHttpRequestResponse makeHttpRequest(IHttpService iHttpService, byte[] bytes) {
        return null;
    }

    @Override
    public byte[] makeHttpRequest(String s, int i, boolean b, byte[] bytes) {
        return new byte[0];
    }

    @Override
    public boolean isInScope(URL url) {
        return false;
    }

    @Override
    public void includeInScope(URL url) {

    }

    @Override
    public void excludeFromScope(URL url) {

    }

    @Override
    public void issueAlert(String s) {

    }

    @Override
    public IHttpRequestResponse[] getProxyHistory() {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpRequestResponse[] getSiteMap(String s) {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IScanIssue[] getScanIssues(String s) {
        return new IScanIssue[0];
    }

    @Override
    public void generateScanReport(String s, IScanIssue[] iScanIssues, File file) {

    }

    @Override
    public List<ICookie> getCookieJarContents() {
        return null;
    }

    @Override
    public void updateCookieJar(ICookie iCookie) {

    }

    @Override
    public void addToSiteMap(IHttpRequestResponse iHttpRequestResponse) {

    }

    @Override
    public void restoreState(File file) {

    }

    @Override
    public void saveState(File file) {

    }

    @Override
    public Map<String, String> saveConfig() {
        return null;
    }

    @Override
    public void loadConfig(Map<String, String> map) {

    }

    @Override
    public String saveConfigAsJson(String... strings) {
        return null;
    }

    @Override
    public void loadConfigFromJson(String s) {

    }

    @Override
    public void setProxyInterceptionEnabled(boolean b) {

    }

    @Override
    public String[] getBurpVersion() {
        return new String[0];
    }

    @Override
    public String getExtensionFilename() {
        return null;
    }

    @Override
    public boolean isExtensionBapp() {
        return false;
    }

    @Override
    public void exitSuite(boolean b) {

    }

    @Override
    public ITempFile saveToTempFile(byte[] bytes) {
        return null;
    }

    @Override
    public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse iHttpRequestResponse) {
        return null;
    }

    @Override
    public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse iHttpRequestResponse, List<int[]> list, List<int[]> list1) {
        return null;
    }

    @Override
    public String getToolName(int i) {
        return null;
    }

    @Override
    public void addScanIssue(IScanIssue iScanIssue) {

    }

    @Override
    public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
        return null;
    }

    @Override
    public String[][] getParameters(byte[] bytes) {
        return new String[0][];
    }

    @Override
    public String[] getHeaders(byte[] bytes) {
        return new String[0];
    }

    @Override
    public void registerMenuItem(String s, IMenuItemHandler iMenuItemHandler) {

    }
}
