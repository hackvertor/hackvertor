package burp.hv.ai;

import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

import static burp.hv.HackvertorExtension.generalSettings;
import static burp.hv.HackvertorExtension.print;

public class SummariseCode {

    private SummariseCode(){}
    public static String getSummary(String language, String code) {
        AI ai = new AI();
        ai.setBypassRateLimit(true);
        ai.setTemperature(0.0);
        ai.setSystemMessage("""
                You are a"""+" "+language+" "+"""
                expert. The user has already defined the variable "input".
                You should take some input from the user as"""+" "+language+" "+"""
                code. You should concisely summarise what the code does in one or two sentences and return it in your response. 
                In addition you should provide a test input and expected output in your summary.
                Do not describe or explain anything. Do not use Markdown. Output plain text.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
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
            print("--SummariseCode--");
            print("Response:" + response);
            print("--End SummariseCode--");
        }
        return response;
    }
}
