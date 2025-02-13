package burp.hv.ai;

import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;

import static burp.hv.HackvertorExtension.generalSettings;
import static burp.hv.HackvertorExtension.print;

public class ExtractFunctionBody {

    private ExtractFunctionBody(){}
    public static String extract(String language, String code) {
        AI ai = new AI();
        ai.setBypassRateLimit(true);
        ai.setTemperature(0.0);
        ai.setSystemMessage("""
                You are a"""+" "+language+" "+"""
                expert. 
                You should take some input from the user as"""+" "+language+" "+"""
                code. You should extract the body of the function provided and return it in your response.
                If there is no function simply return the code. 
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
            print("--ExtractFunctionBody--");
            print("Response:" + response);
            print("--End ExtractFunctionBody--");
        }
        return response;
    }
}
