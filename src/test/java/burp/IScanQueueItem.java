package burp;

public interface IScanQueueItem {
    String getStatus();
    byte getPercentageComplete();
    int getNumRequestsMade();
    int getNumRequestsQueued();
    int getNumErrorsGenerated();
    IScanIssue[] getIssues();
    void cancel();
}