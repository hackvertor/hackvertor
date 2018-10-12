package burp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class Ngrams {
    private Map<String, Double> ngrams;
    private int length;
    private double floor;
    private String input;
    Ngrams(String filename) throws IOException {
        String gramLines = readFile(filename);
        String[] lines = gramLines.split("\n");
        double n = 0;
        String lastKey = "";
        Map<String, Integer> ngramsSum = new HashMap<>();
        Map<String, Double> ngramsLookup = new HashMap<>();
        for(int i = 0;i<lines.length;i++) {
            String[] line = lines[i].split(" ");
            String key = line[0];
            lastKey = key;
            int count = Integer.parseInt(line[1]);
            n += count;
            ngramsSum.put(key, count);
        }
        length = lastKey.length();
        for(Map.Entry<String, Integer> entry : ngramsSum.entrySet()) {
            String key = entry.getKey();
            int value = entry.getValue();
            ngramsLookup.put(key, Math.log10((value)/n));
        }
        this.ngrams = ngramsLookup;
        floor = Math.log10(0.01/n);
    }
    public Double getScore() {
        double score = 0;
        String str = input.toUpperCase();
        str = str.replaceAll("[^A-Z]", "");
        for(int i=0;i<str.length()-length+1;i++) {
            String text = str.substring(i,i+length);
            if(ngrams.containsKey(text)) {
                score += ngrams.get(text);
            } else {
                score += floor;
            }
        }
        return score;
    }
    public void setInput(String input) {
        this.input = input;
    }
    private String readFile(String filename) throws IOException
    {
        URL url = getClass().getResource(filename);
        InputStream is = url.openStream();
        StringBuilder sb = new StringBuilder();
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        String read;

        while ((read = br.readLine()) != null)
        {
            sb.append(read+"\n");
        }

        br.close();
        return sb.toString();
    }
}
