package burp.stubs;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class StubMontoyaApi {

    public static MontoyaApi withInMemoryPersistence() {
        Map<String, Object> preferenceValues = new HashMap<>();
        Preferences preferences = (Preferences) Proxy.newProxyInstance(loader(), new Class[]{Preferences.class},
                (proxy, method, arguments) -> {
                    if (method.getName().startsWith("set")) {
                        preferenceValues.put((String) arguments[0], arguments[1]);
                        return null;
                    }
                    if (method.getName().startsWith("get")) {
                        return preferenceValues.get(arguments[0]);
                    }
                    return null;
                });
        Map<String, Object> extensionDataValues = new HashMap<>();
        PersistedObject extensionData = (PersistedObject) Proxy.newProxyInstance(loader(),
                new Class[]{PersistedObject.class},
                (proxy, method, arguments) -> {
                    if (method.getName().startsWith("set")) {
                        extensionDataValues.put((String) arguments[0], arguments[1]);
                        return null;
                    }
                    if (method.getName().startsWith("get")) {
                        return extensionDataValues.get(arguments[0]);
                    }
                    return null;
                });
        Persistence persistence = (Persistence) Proxy.newProxyInstance(loader(), new Class[]{Persistence.class},
                (proxy, method, arguments) -> method.getName().equals("preferences") ? preferences : extensionData);
        return (MontoyaApi) Proxy.newProxyInstance(loader(), new Class[]{MontoyaApi.class},
                (proxy, method, arguments) -> method.getName().equals("persistence") ? persistence : null);
    }

    private static ClassLoader loader() {
        return StubMontoyaApi.class.getClassLoader();
    }
}
