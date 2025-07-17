package burp;

import java.util.List;

public interface IScannerCheck {
    List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse);
    List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);
    int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue);
}