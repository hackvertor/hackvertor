package hackvertor;

public class Tag {
    public enum Category {
        Custom, Variables, Encode, Decode, String, Convert, Conditions, Math, Hash, HMAC, Fake, Charsets, Compression, Date, Encrypt, Decrypt, Languages, System, XSS
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
