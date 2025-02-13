package burp.hv.settings;

public class UnregisteredSettingException extends Exception {
    public UnregisteredSettingException() {
        super("Setting not registered");
    }

    public UnregisteredSettingException(String message) {
        super(message);
    }

    public UnregisteredSettingException(String message, Throwable cause) {
        super(message, cause);
    }
}
