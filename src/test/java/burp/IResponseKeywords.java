package burp;

import java.util.List;

public interface IResponseKeywords {
    List<String> getKeywords();
    int getKeywordCount(String keyword, int responseIndex);
    void updateWith(byte[]... responses);
}