package burp.hv.ai;

import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptOptions;
import burp.api.montoya.ai.chat.PromptResponse;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static burp.hv.HackvertorExtension.*;

public class AI {
    public static LimitedHashMap<String, String> responseCache = new LimitedHashMap<>(20);

    public static final String featureMessage = "This feature is only available on the AI version of Burp.";
    public static long lastExecutionTime = 0;
    public static long apiRequestLimitMS = 1000;
    private String systemMessage;
    private String prompt;
    private double temperature;
    private boolean bypassRateLimit = false;
    public void setBypassRateLimit(boolean bypassRateLimit) {
         this.bypassRateLimit = bypassRateLimit;
    }

    public void setSystemMessage(String systemMessage) {
         this.systemMessage = systemMessage;
    }

    public void setPrompt(String prompt) {
         this.prompt = prompt;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public String getPrompt() {
         return this.prompt;
    }

    public static boolean isAiSupported() {
        return montoyaApi != null && hasApiMethod(montoyaApi, "ai") && montoyaApi.ai().isEnabled();
    }

    public String getSystemMessage() {
        return this.systemMessage;
    }
    public static boolean hasApiMethod(Object obj, String methodName) {
         try {
             Class<?> clazz = obj.getClass();
             clazz.getMethod(methodName);
             return true;
         } catch(NoSuchMethodException e){
             return false;
         }
    }

    public static String getHash(String input) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(input.getBytes());
        return new String(messageDigest.digest());
    }
    public String execute() {
        try {
            if(!isAiSupported()) {
                throw new RuntimeException("Montoya AI API is not enabled. You need to enable use AI in the extension tab.");
            }
            String hash = getHash(this.temperature + this.systemMessage + this.prompt);
            if(AI.responseCache.containsKey(hash)) {
                return AI.responseCache.get(hash);
            }
            if(!bypassRateLimit) {
                checkLastExecutionTime();
            }
            PromptResponse response = montoyaApi.ai().prompt().execute(PromptOptions.promptOptions().withTemperature(this.temperature), Message.systemMessage(this.systemMessage), Message.userMessage(this.prompt));
            AI.responseCache.put(hash, response.content());
            return response.content();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public void checkLastExecutionTime() {
        long now = System.currentTimeMillis();
        if(AI.lastExecutionTime > 0) {
            long diff = now - AI.lastExecutionTime;
            if(diff < AI.apiRequestLimitMS) {
                AI.lastExecutionTime = now;
                throw new RuntimeException("API request limit hit. Please wait a few seconds.");
            }
        }
        AI.lastExecutionTime = now;
    }
}
