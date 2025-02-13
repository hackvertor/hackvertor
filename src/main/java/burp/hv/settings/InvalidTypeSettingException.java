package burp.hv.settings;

public class InvalidTypeSettingException extends Exception {
    public InvalidTypeSettingException() {
        super("Incorrect type");
    }

    public InvalidTypeSettingException(String message) {
        super(message);
    }

    public InvalidTypeSettingException(String message, Throwable cause) {
        super(message, cause);
    }
}
