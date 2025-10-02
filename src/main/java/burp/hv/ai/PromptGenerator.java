package burp.hv.ai;
import burp.IParameter;
import burp.IRequestInfo;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

import static burp.hv.HackvertorExtension.generalSettings;
import static burp.hv.HackvertorExtension.print;

public class PromptGenerator {
    private PromptGenerator(){}

    public static String generateConversionPrompt(JSONArray existingPrompts, JSONArray headersAndParameters) {
        boolean debugAi;
        try {
            debugAi = generalSettings.getBoolean("debugAi");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            throw new RuntimeException(e);
        }
        AI ai = new AI();
        String existingPromptsText = "";
        if(!existingPrompts.isEmpty()) {
            existingPromptsText = "Here are a list of existing prompt names and a summary of what they do, if you find any that do the same thing to these do not add the generated prompt to the JSON array ";
            existingPromptsText += existingPrompts;
        }
        ai.setBypassRateLimit(true);
        ai.setSystemMessage("""
                            You are a web security expert.
                            Your job is to find potential encodings that can be used for web security.
                            You should then create two prompts that can be used for an LLM. One that will encode and one that will decode the discovered encoding.
                            The user will send you a list of headers or parameters for you to analyse in JSON, you should analyse them and look how you can create a prompt that either encodes or decodes the found data. 
                            You should always try to prioritise the most interesting encoding unless it already exists in the existing prompts.                           
                            You should not include the data found in this prompt.
                            If you don't find anything just respond with an empty JSON array.
                            Return an empty JSON array if the encodings you've found already exist in the list of existing prompts.
                            Do not output markdown. Do not describe what you are doing just return JSON.                          
                            You should respond with a JSON array and give your prompt a name that matches this regex "^[a-z0-9_]+$".
                            The first prompt name should contain encode and the second prompt name should contain decode.
                            The JSON returned should contain a tests property where a list of tests are added to ensure the prompt works as expected.
                            You should always use more than one character in the input of the tests to ensure it works correctly.
                            The JSON structure should be:[{"prompt":"$yourprompt","name":"$promptname","tests":[{"input":"$input","expectedOutput":"$expectedOutput"}]}]
                            \nEnsure that $yourprompt, $input and $expectedOutput is correctly escaped according to the JSON specification.
                            Your response should be a valid JSON array that conforms to the JSON specification.
                            Validate your JSON response and ensure it's valid JSON.
                            You should correctly escape all strings in the JSON.
                            """+existingPromptsText+"""  
                            . You should parse the following JSON and then look for encodings in it.
                            Do not make encodings up. They should exist in the JSON you are analysing.
                            Here is a list of headers and parameters for you to analyse in JSON:
                            """);

        ai.setPrompt(headersAndParameters.toString());
        ai.setTemperature(0.0);
        if(debugAi) {
            print("--PromptGenerator--");
            print(ai.getSystemMessage() + "\n\n");
            print(ai.getPrompt() + "\n\n");
            print("--end PromptGenerator--");
        }
        String response = ai.execute().trim();
        if(debugAi) {
            print("--PromptGenerator--");
            print(response + "\n\n");
            print("--end PromptGenerator--");
        }
        return response;
    }
}
