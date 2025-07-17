package burp;

import java.util.Map;

public interface IBurpCollaboratorInteraction {
    String getProperty(String name);
    Map<String, String> getProperties();
}