package burp.hv.ai;

import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import org.json.JSONObject;

import static burp.hv.HackvertorExtension.*;

public class CodeConversion {

    private CodeConversion(){}
    public static String promptToCode(String language, JSONObject aiPrompt, String additionalInstructions) {
        AI codeConversionAi = new AI();
        codeConversionAi.setBypassRateLimit(true);
        codeConversionAi.setTemperature(0.0);
        codeConversionAi.setSystemMessage("""
                Do not decode anything. Do not output markdown. Only output a""" + " " + language +" function" + """
                \nDo not describe anything. Do not explain anything.
                You are a""" + " " + language + """
                 expert. Your code should not contain any comments.
                """ + additionalInstructions + """
                You should not use any external libraries.
                You are going to get an LLM prompt from the user which you should convert to a""" + " " + language + " " + """
                function. The function should be called""" + " " + aiPrompt.getString("name") + "." + """
                \nUse the following JSON as a list of tests to run to ensure the function works by using the input of the test and ensure it matches the expected value:""" + " " +aiPrompt.getJSONArray("tests") + " " + """               
                Your code should be clear and concise and you should always return valid""" + " " + language +" function"+ """                                        
                . DO NOT EMBED THE TESTS IN THE CODE, USE THE TESTS TO VERIFY THE CODE.
                DO NOT INCLUDE TESTS IN THE FINAL CODE ONLY USE THE TESTS TO VERIFY THE FUNCTION WORKS.
                DO NOT INCLUDE PRINT STATEMENTS.
                REMOVE ALL COMMENTS AND TESTS BEFORE RETURNING THE """ + " " + language.toUpperCase() + " FUNCTION." + """
                \nOutput a""" + " " + language + " " + """
                function. Do not output markdown.
                """);
        boolean debugAi;
        try {
            debugAi = generalSettings.getBoolean("debugAi");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            throw new RuntimeException(e);
        }
        if (debugAi) {
            print("--CodeConversion--");
            print("Generate code prompt:" + codeConversionAi.getSystemMessage() + "\n" + codeConversionAi.getPrompt());
            print("--End CodeConversion--");
        }
        codeConversionAi.setPrompt(aiPrompt.getString("prompt"));
        String response = removeMarkdownMarkers(codeConversionAi.execute(), language);
        if (debugAi) {
            print("--CodeConversion--");
            print("Response:" + response);
            print("--End CodeConversion--");
        }
        return response;
    }

    public static String removeMarkdownMarkers(String input, String language) {
        return input.trim().replaceAll("^(?i)```" + language, "").replaceAll("```$","").trim();
    }
}
