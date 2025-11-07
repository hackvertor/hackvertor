package burp.hv.ui;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import static burp.hv.HackvertorExtension.montoyaApi;

public class HackvertorHistory {
    private static final int MAX_HISTORY_SIZE = 1000;
    private static final int MAX_INPUT_LENGTH = 50000;
    private static final int MAX_OUTPUT_LENGTH = 100000;
    private static final String HISTORY_SETTING_KEY = "hackvertorHistory";

    private final List<HistoryEntry> history;
    private int currentIndex = -1;
    private final boolean isMessageEditor;

    public static class HistoryEntry {
        private final String input;
        private final String output;
        private final long timestamp;

        public HistoryEntry(String input, String output) {
            this.input = truncateString(input, MAX_INPUT_LENGTH);
            this.output = truncateString(output, MAX_OUTPUT_LENGTH);
            this.timestamp = System.currentTimeMillis();
        }

        private static String truncateString(String str, int maxLength) {
            if (str == null) return "";
            return str.length() > maxLength ? str.substring(0, maxLength) : str;
        }

        public String getInput() {
            return input;
        }

        public String getOutput() {
            return output;
        }

        public long getTimestamp() {
            return timestamp;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            HistoryEntry that = (HistoryEntry) obj;
            return input.equals(that.input) && output.equals(that.output);
        }

        @Override
        public int hashCode() {
            return input.hashCode() * 31 + output.hashCode();
        }
    }

    public HackvertorHistory(boolean isMessageEditor) {
        this.isMessageEditor = isMessageEditor;
        this.history = loadHistory();
        if (!history.isEmpty()) {
            currentIndex = history.size() - 1;
        }
    }

    public HackvertorHistory() {
        this(false);
    }

    public void addEntry(String input, String output) {
        if (input == null || input.trim().isEmpty()) {
            return;
        }

        HistoryEntry newEntry = new HistoryEntry(input, output);

        // Check if this entry is the same as the last one
        if (!history.isEmpty()) {
            HistoryEntry lastEntry = history.get(history.size() - 1);
            if (lastEntry.getInput().equals(newEntry.getInput()) &&
                lastEntry.getOutput().equals(newEntry.getOutput())) {
                return;
            }
        }

        history.add(newEntry);

        while (history.size() > MAX_HISTORY_SIZE) {
            history.remove(0);
        }

        currentIndex = history.size() - 1;
        saveHistory();
    }

    public HistoryEntry getPrevious() {
        if (history.isEmpty()) {
            return null;
        }

        if (currentIndex > 0) {
            currentIndex--;
        } else {
            currentIndex = history.size() - 1;
        }

        return history.get(currentIndex);
    }

    public HistoryEntry getNext() {
        if (history.isEmpty()) {
            return null;
        }

        if (currentIndex < history.size() - 1) {
            currentIndex++;
        } else {
            currentIndex = 0;
        }

        return history.get(currentIndex);
    }

    public HistoryEntry getFirst() {
        if (history.isEmpty()) {
            return null;
        }

        currentIndex = 0;
        return history.get(currentIndex);
    }

    public HistoryEntry getLast() {
        if (history.isEmpty()) {
            return null;
        }

        currentIndex = history.size() - 1;
        return history.get(currentIndex);
    }

    public void clear() {
        history.clear();
        currentIndex = -1;
        saveHistory();
    }

    public int size() {
        return history.size();
    }

    public boolean isEmpty() {
        return history.isEmpty();
    }

    private List<HistoryEntry> loadHistory() {
        // Message editor maintains local history only - don't load from persistence
        if (isMessageEditor) {
            return new ArrayList<>();
        }

        if (montoyaApi == null) {
            return new ArrayList<>();
        }

        try {
            String content = montoyaApi.persistence().extensionData().getString(HISTORY_SETTING_KEY);
            if (content == null || content.isEmpty()) {
                return new ArrayList<>();
            }

            JSONArray jsonArray = new JSONArray(content);
            List<HistoryEntry> loaded = new ArrayList<>();

            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                String input = obj.getString("input");
                String output = obj.getString("output");
                loaded.add(new HistoryEntry(input, output));
            }

            return loaded;
        } catch (Exception e) {
            System.err.println("Failed to load history: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    private void saveHistory() {
        // Message editor maintains local history only - don't save to persistence
        if (isMessageEditor) {
            return;
        }

        if (montoyaApi == null) {
            return;
        }

        try {
            JSONArray jsonArray = new JSONArray();
            for (HistoryEntry entry : history) {
                JSONObject obj = new JSONObject();
                obj.put("input", entry.getInput());
                obj.put("output", entry.getOutput());
                obj.put("timestamp", entry.getTimestamp());
                jsonArray.put(obj);
            }

            montoyaApi.persistence().extensionData().setString(HISTORY_SETTING_KEY, jsonArray.toString());
        } catch (Exception e) {
            System.err.println("Failed to save history: " + e.getMessage());
        }
    }

    public void resetIndex() {
        if (!history.isEmpty()) {
            currentIndex = history.size() - 1;
        }
    }

    public int getCurrentIndex() {
        return currentIndex;
    }

    public void reloadFromPersistence() {
        // Only reload for non-message editor histories
        if (isMessageEditor) {
            return;
        }

        List<HistoryEntry> newHistory = loadHistory();

        // Preserve the current entry if possible
        HistoryEntry currentEntry = null;
        if (currentIndex >= 0 && currentIndex < history.size()) {
            currentEntry = history.get(currentIndex);
        }

        // Replace the history with the reloaded one
        history.clear();
        history.addAll(newHistory);

        // Try to find the same entry in the new history
        if (currentEntry != null && !history.isEmpty()) {
            int foundIndex = -1;
            for (int i = history.size() - 1; i >= 0; i--) {
                if (history.get(i).equals(currentEntry)) {
                    foundIndex = i;
                    break;
                }
            }

            if (foundIndex >= 0) {
                currentIndex = foundIndex;
            } else {
                // If not found, go to the latest entry
                currentIndex = history.size() - 1;
            }
        } else if (!history.isEmpty()) {
            currentIndex = history.size() - 1;
        } else {
            currentIndex = -1;
        }
    }
}