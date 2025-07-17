package burp;

import java.net.URL;

public interface IScanIssue {
    URL getUrl();
    String getIssueName();
    int getIssueType();
    String getSeverity();
    String getConfidence();
    String getIssueBackground();
    String getRemediationBackground();
    String getIssueDetail();
    String getRemediationDetail();
    IHttpRequestResponse[] getHttpMessages();
    IHttpService getHttpService();
}