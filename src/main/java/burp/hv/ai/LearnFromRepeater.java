package burp.hv.ai;

import burp.hv.HackvertorExtension;
import burp.hv.tags.CustomTags;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

public class LearnFromRepeater {
    public static void learn(JSONArray headersAndParameters, boolean allowAiToGenerateCode) {
        HackvertorExtension.executorService.submit(() -> {
            try {
                String json = HackvertorExtension.callbacks.loadExtensionSetting("customTags");
                JSONArray existingTags;
                if (json != null && !json.isEmpty()) {
                    existingTags = new JSONArray(json);
                } else {
                    existingTags = new JSONArray();
                }
                JSONArray existingPrompts = new JSONArray();
                for (int i = 0; i < existingTags.length(); i++) {
                    JSONObject existingTag = (JSONObject) existingTags.get(i);
                    JSONObject obj = new JSONObject();
                    obj.put("name", existingTag.getString("tagName").replaceFirst("^_", ""));
                    if (existingTag.has("summary")) {
                        obj.put("summary", existingTag.getString("summary"));
                    }
                    existingPrompts.put(obj);
                }
                String response = PromptGenerator.generateConversionPrompt(existingPrompts, headersAndParameters);
                JSONArray prompts = new JSONArray(response);
                CustomTags.loadCustomTags();
                for (int i = 0; i < prompts.length(); i++) {
                    JSONObject aiPrompt = (JSONObject) prompts.get(i);
                    if (HackvertorExtension.hackvertor.hasCustomTag(aiPrompt.getString("name"))) {
                        continue;
                    }

                    if (allowAiToGenerateCode) {
                        String pythonCode = CodeConversion.promptToCode("Python", aiPrompt, "The code generated should run on Python 2.7\n") + "\noutput = " + aiPrompt.getString("name") + "(input)";
                        if(!CustomTags.createCustomTag(aiPrompt.getString("name"), "Python", pythonCode, "", "", "", "", "", "", 0)) {
                            HackvertorExtension.stderr.println("Tag with the same name already exists: " + aiPrompt.getString("name"));
                        }
                    } else {
                        if(!CustomTags.createCustomTag(aiPrompt.getString("name"), "AI", aiPrompt.getString("prompt"), "temperature", "String", "1.0", "", "", "", 1)) {
                            HackvertorExtension.stderr.println("Tag with the same name already exists: " + aiPrompt.getString("name"));
                        }
                    }
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                HackvertorExtension.montoyaApi.logging().logToError(writer.toString());
            } finally {
                HackvertorExtension.extensionPanel.refresh();
            }
        });
    }
}
