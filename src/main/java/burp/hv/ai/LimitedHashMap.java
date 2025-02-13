package burp.hv.ai;
import java.util.LinkedHashMap;
import java.util.Map;

public class LimitedHashMap<K, V> extends LinkedHashMap<K, V> {
    private final int maxSize;

    public LimitedHashMap(int maxSize) {
        this.maxSize = maxSize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > maxSize;
    }
}