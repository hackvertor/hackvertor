package burp;

import java.util.List;

public interface IBurpCollaboratorClientContext {
    IBurpCollaboratorInteraction[] fetchCollaboratorInteractionsFor(String payload);
    IBurpCollaboratorInteraction[] fetchAllCollaboratorInteractions();
    String generatePayload(boolean includeCollaboratorServerLocation);
    String getCollaboratorServerLocation();
}