package burp;

public class Tag {
    public enum Category {
        Charsets, Compression, Encrypt, Decrypt, Encode, Date, Decode, Convert, String, Hash, HMAC, Math, XSS, Variables, Loops, Languages, Custom
    };

    public Category category;
    public String name;
    public boolean hasInput = true;
    public String tooltip;
    public TagArgument argument1 = null;
    public TagArgument argument2 = null;
    public TagArgument argument3 = null;
    public TagArgument argument4 = null;

    Tag(Category tagCategory, String tagName, boolean hasInput, String tooltip) {
        this.category = tagCategory;
        this.name = tagName;
        this.hasInput = hasInput;
        this.tooltip = tooltip;
    }
}
