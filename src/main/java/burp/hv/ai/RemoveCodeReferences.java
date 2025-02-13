package burp.hv.ai;

import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

import static burp.hv.HackvertorExtension.generalSettings;
import static burp.hv.HackvertorExtension.print;

public class RemoveCodeReferences {

    private RemoveCodeReferences(){}
    public static String remove(String language, String code) {
        AI ai = new AI();
        ai.setBypassRateLimit(true);
        ai.setTemperature(0.0);
        ai.setSystemMessage("""
                You are a"""+" "+language+" "+"""
                expert. Your job is to go through the"""+" "+language+" "+"""
                code supplied by the user and remove every variable, function argument and reference and return the final result. 
                Do not describe or explain anything. Do not use Markdown. Output plain text                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
                """);
        boolean debugAi;
        try {
            debugAi = generalSettings.getBoolean("debugAi");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            throw new RuntimeException(e);
        }
        ai.setPrompt(code);
        String response = ai.execute().trim();
        if (debugAi) {
            print("--RemoveCodeReferences--");
            print("Response:" + response);
            print("--End RemoveCodeReferences--");
        }
        return response;
    }
}
