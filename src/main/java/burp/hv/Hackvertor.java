package burp.hv;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.hv.tags.CustomTags;
import burp.hv.tags.Tag;
import burp.hv.tags.TagArgument;
import burp.hv.utils.TagUtils;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

import static burp.hv.HackvertorExtension.*;

public class Hackvertor {
    private ArrayList<Tag> tags = new ArrayList<Tag>();
    private JSONArray customTags = new JSONArray();
    private HttpRequest request;

    // Faker registry to replace reflection-based approach
    private static final Map<String, List<String>> FAKER_PROPERTIES = new HashMap<>();

    static {
        initializeFakerProperties();
    }

    private static void initializeFakerProperties() {
        // Address properties
        FAKER_PROPERTIES.put("address", Arrays.asList(
            "$buildingNumber", "$city", "$cityName", "$cityPrefix", "$citySuffix",
            "$country", "$countryCode", "$firstName", "$fullAddress", "$lastName",
            "$latitude", "$longitude", "$secondaryAddress", "$state", "$stateAbbr",
            "$streetAddress", "$streetAddressNumber", "$streetName", "$streetPrefix",
            "$streetSuffix", "$timeZone", "$zipCode", "$zipCodePlus4"
        ));

        // Ancient properties
        FAKER_PROPERTIES.put("ancient", Arrays.asList(
            "$god", "$hero", "$primordial", "$titan"
        ));

        // Animal properties
        FAKER_PROPERTIES.put("animal", Arrays.asList("$name"));

        // App properties
        FAKER_PROPERTIES.put("app", Arrays.asList(
            "$author", "$name", "$version"
        ));

        // Artist properties
        FAKER_PROPERTIES.put("artist", Arrays.asList("$name"));

        // Avatar properties
        FAKER_PROPERTIES.put("avatar", Arrays.asList("$image"));

        // Aviation properties
        FAKER_PROPERTIES.put("aviation", Arrays.asList(
            "$aircraft", "$airport", "$METAR"
        ));

        // Book properties
        FAKER_PROPERTIES.put("book", Arrays.asList(
            "$author", "$genre", "$publisher", "$title"
        ));

        // Bool properties
        FAKER_PROPERTIES.put("bool", Arrays.asList("$bool"));

        // Business properties
        FAKER_PROPERTIES.put("business", Arrays.asList("$creditCardExpiry", "$creditCardNumber", "$creditCardType"));

        // Code properties
        FAKER_PROPERTIES.put("code", Arrays.asList(
            "$asin", "$ean13", "$ean8", "$gtin13", "$gtin8",
            "$imei", "$isbn10", "$isbn13", "$isbnGroup", "$isbnGs1", "$isbnRegistrant"
        ));

        // Currency properties
        FAKER_PROPERTIES.put("currency", Arrays.asList("$code", "$name"));

        // Color properties
        FAKER_PROPERTIES.put("color", Arrays.asList("$hex", "$name"));

        // Commerce properties
        FAKER_PROPERTIES.put("commerce", Arrays.asList(
            "$color", "$department", "$material", "$price", "$productName", "$promotionCode"
        ));

        // Company properties
        FAKER_PROPERTIES.put("company", Arrays.asList(
            "$bs", "$buzzword", "$catchPhrase", "$industry",
            "$logo", "$name", "$profession", "$suffix", "$url"
        ));

        // Crypto properties
        FAKER_PROPERTIES.put("crypto", Arrays.asList("$md5", "$sha1", "$sha256", "$sha512"));

        // Date properties
        FAKER_PROPERTIES.put("date", Arrays.asList("$birthday"));

        // Demographic properties
        FAKER_PROPERTIES.put("demographic", Arrays.asList(
            "$demonym", "$educationalAttainment", "$maritalStatus", "$race", "$sex"
        ));

        // Educator properties
        FAKER_PROPERTIES.put("educator", Arrays.asList(
            "$campus", "$course", "$secondarySchool", "$university"
        ));

        // File properties
        FAKER_PROPERTIES.put("file", Arrays.asList("$extension", "$fileName", "$mimeType"));

        // Finance properties
        FAKER_PROPERTIES.put("finance", Arrays.asList(
            "$bic", "$creditCard", "$iban"
        ));

        // Food properties
        FAKER_PROPERTIES.put("food", Arrays.asList(
            "$dish", "$fruit", "$ingredient", "$measurement", "$spice", "$sushi", "$vegetable"
        ));

        // Hacker properties
        FAKER_PROPERTIES.put("hacker", Arrays.asList(
            "$abbreviation", "$adjective", "$ingverb", "$noun", "$verb"
        ));

        // IdNumber properties
        FAKER_PROPERTIES.put("idNumber", Arrays.asList(
            "$invalid", "$invalidSvSeSsn", "$ssnValid", "$valid", "$validSvSeSsn"
        ));

        // Internet properties
        FAKER_PROPERTIES.put("internet", Arrays.asList(
            "$avatar", "$domainName", "$domainSuffix", "$domainWord",
            "$emailAddress", "$image", "$ipV4Address", "$ipV4Cidr", "$ipV6Address",
            "$ipV6Cidr", "$macAddress", "$password", "$privateIpV4Address",
            "$publicIpV4Address", "$safeEmailAddress", "$slug", "$url", "$userAgent", "$uuid"
        ));

        // Job properties
        FAKER_PROPERTIES.put("job", Arrays.asList("$field", "$keySkills", "$position", "$seniority", "$title"));

        // Lorem properties
        FAKER_PROPERTIES.put("lorem", Arrays.asList(
            "$character", "$characters", "$fixedString", "$paragraph", "$sentence", "$word"
        ));

        // Music properties
        FAKER_PROPERTIES.put("music", Arrays.asList("$chord", "$genre", "$instrument", "$key"));

        // Name properties
        FAKER_PROPERTIES.put("name", Arrays.asList(
            "$bloodGroup", "$firstName", "$fullName", "$lastName",
            "$name", "$nameWithMiddle", "$prefix", "$suffix", "$title", "$username"
        ));

        // Nation properties
        FAKER_PROPERTIES.put("nation", Arrays.asList(
            "$capitalCity", "$flag", "$language", "$nationality"
        ));

        // Number properties
        FAKER_PROPERTIES.put("number", Arrays.asList(
            "$digit", "$digits", "$negative", "$positive"
        ));

        // Options properties
        FAKER_PROPERTIES.put("options", Arrays.asList("$option"));

        // PhoneNumber properties
        FAKER_PROPERTIES.put("phoneNumber", Arrays.asList(
            "$cellPhone", "$phoneNumber", "$phoneNumberInternational", "$phoneNumberNational",
            "$phoneNumberWithExtension", "$tollFreePhoneNumber"
        ));

        // SlackEmoji properties
        FAKER_PROPERTIES.put("slackEmoji", Arrays.asList(
            "$activity", "$celebration", "$custom", "$emoji",
            "$foodAndDrink", "$nature", "$people"
        ));

        // Space properties
        FAKER_PROPERTIES.put("space", Arrays.asList(
            "$agency", "$agencyAbbreviation", "$company", "$constellation",
            "$distanceMeasurement", "$galaxy", "$meteorite", "$moon", "$nasaSpaceCraft",
            "$nebula", "$planet", "$star", "$starCluster"
        ));

        // Stock properties
        FAKER_PROPERTIES.put("stock", Arrays.asList("$nsdqSymbol", "$nyseSymbol"));

        // Team properties
        FAKER_PROPERTIES.put("team", Arrays.asList("$creature", "$name", "$sport", "$state"));

        // University properties
        FAKER_PROPERTIES.put("university", Arrays.asList("$name", "$prefix", "$suffix"));

        // Weather properties
        FAKER_PROPERTIES.put("weather", Arrays.asList("$description", "$temperatureCelsius", "$temperatureFahrenheit"));
    }
    public Hackvertor(){
        init();
    }

    public HttpRequest getRequest() {
        return request;
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public boolean hasCustomTag(String tagName) {
        tagName = "_" + tagName;
        JSONArray customTags = this.getCustomTags();
        int len = customTags.length();
        for (int i = 0; i < len; i++) {
            JSONObject customTag = (JSONObject) customTags.get(i);
            if (tagName.equals(customTag.getString("tagName"))) {
                return true;
            }
        }
        return false;
    }

    public static String removeHackvertorTags(String input) {
        try {
            input = HackvertorParser.parse(input).stream()
                    .filter(element -> element instanceof Element.TextElement)
                    .map(element -> ((Element.TextElement) element).getContent())
                    .collect(Collectors.joining());
        }catch (ParseException ex){
            //TODO Better error handling.
            ex.printStackTrace();
        }
        return input;
    }

    void init() {
        initCharsetTags();
        initCompressionTags();
        initDateTags();
        initEncryptDecryptTags();
        initEncodingTags();
        initDecodingTags();
        initConditionTags();
        initConvertTags();
        initStringTags();
        generateFakeTags();
        initHMACTags();
        initHashTags();
        initMathTags();
        initXSSTags();
        initVariableTags();
        initLanguageTags();
        initSystemTags();
        initCustomTags();
    }

    // Helper methods for elegant tag creation
    private void addTag(Tag.Category category, String name, boolean hasInput, String description) {
        tags.add(new Tag(category, name, hasInput, description));
    }

    private void addTag(Tag.Category category, String name, boolean hasInput, String description,
                       Object... args) {
        Tag tag = new Tag(category, name, hasInput, description);
        setArguments(tag, args);
        tags.add(tag);
    }

    private void setArguments(Tag tag, Object... args) {
        if (args.length >= 2) {
            tag.argument1 = new TagArgument(args[0].toString(), args[1].toString());
        }
        if (args.length >= 4) {
            tag.argument2 = new TagArgument(args[2].toString(), args[3].toString());
        }
        if (args.length >= 6) {
            tag.argument3 = new TagArgument(args[4].toString(), args[5].toString());
        }
        if (args.length >= 8) {
            tag.argument4 = new TagArgument(args[6].toString(), args[7].toString());
        }
    }

    private static class TagBuilder {
        private final Tag.Category category;
        private final String name;
        private final boolean hasInput;
        private final String description;
        private final List<TagArgument> arguments = new ArrayList<>();

        public TagBuilder(Tag.Category category, String name, boolean hasInput, String description) {
            this.category = category;
            this.name = name;
            this.hasInput = hasInput;
            this.description = description;
        }

        public TagBuilder arg(String type, String value) {
            arguments.add(new TagArgument(type, value));
            return this;
        }

        public Tag build() {
            Tag tag = new Tag(category, name, hasInput, description);
            if (arguments.size() > 0) tag.argument1 = arguments.get(0);
            if (arguments.size() > 1) tag.argument2 = arguments.get(1);
            if (arguments.size() > 2) tag.argument3 = arguments.get(2);
            if (arguments.size() > 3) tag.argument4 = arguments.get(3);
            return tag;
        }
    }

    private void addTag(TagBuilder builder) {
        tags.add(builder.build());
    }

    private void initCharsetTags() {
        SortedMap<String, Charset> charsets = Charset.availableCharsets();
        for (Map.Entry<String, Charset> entry : charsets.entrySet()) {
            Charset charset = entry.getValue();
            if (!charset.canEncode()) {
                continue;
            }
            for (String alias : charset.aliases()) {
                if(!TagUtils.isValidTagName(alias)) {
                    continue;
                }
                addTag(Tag.Category.Charsets, alias, true, alias + "(String input)");
            }
        }

        addTag(Tag.Category.Charsets, "charset_convert", true,
               "charset_convert(String input, String from, String to)",
               "string", "from", "string", "to");
    }

    private void initCompressionTags() {
        addTag(Tag.Category.Compression, "brotli_decompress", true, "brotli_decompress(String str)");
        addTag(Tag.Category.Compression, "gzip_compress", true, "gzip_compress(String str)");
        addTag(Tag.Category.Compression, "gzip_decompress", true, "gzip_decompress(String str)");
        addTag(Tag.Category.Compression, "bzip2_compress", true, "bzip2_compress(String str)");
        addTag(Tag.Category.Compression, "bzip2_decompress", true, "bzip2_decompress(String str)");
        addTag(Tag.Category.Compression, "deflate_compress", true,
               "deflate_compress(String str, Boolean includeHeader)",
               "boolean", "true");
        addTag(Tag.Category.Compression, "deflate_decompress", true,
               "deflate_decompress(String str, Boolean includeHeader)",
               "boolean", "true");
    }

    private void initDateTags() {
        addTag(Tag.Category.Date, "timestamp", false, "timestamp()");
        addTag(Tag.Category.Date, "date", false, "date(String format)",
               "string", "yyyy-MM-dd HH:mm:ss", "string", "GMT");
    }

    private void initEncryptDecryptTags() {
        addTag(Tag.Category.Encrypt, "aes_encrypt", true,
               "aes_encrypt(String plaintext, String key, String transformations)",
               "string", "supersecret12356", "string", "AES/ECB/PKCS5PADDING", "string", "initVector123456");
        addTag(Tag.Category.Decrypt, "aes_decrypt", true,
               "aes_decrypt(String ciphertext, String key, String transformations)",
               "string", "supersecret12356", "string", "AES/ECB/PKCS5PADDING", "string", "initVector123456");
        addTag(Tag.Category.Encrypt, "rotN", true, "rotN(String str, int n)", "int", "13");
        addTag(Tag.Category.Encrypt, "xor", true, "xor(String message, String key)", "string", "key");
        addTag(Tag.Category.Decrypt, "xor_decrypt", true, "xor_decrypt(String ciphertext, int keyLength)", "int", "3");
        addTag(Tag.Category.Encrypt, "xor_getkey", true, "xor_getkey(String ciphertext)");
        addTag(Tag.Category.Encrypt, "affine_encrypt", true,
               "affine_encrypt(String message, int key1, int key2)", "int", "5", "int", "9");
        addTag(Tag.Category.Decrypt, "affine_decrypt", true,
               "affine_decrypt(String ciphertext, int key1, int key2)", "int", "5", "int", "9");
        addTag(Tag.Category.Encrypt, "atbash_encrypt", true, "atbash_encrypt(String message)");
        addTag(Tag.Category.Decrypt, "atbash_decrypt", true, "atbash_decrypt(String ciphertext)");
        addTag(Tag.Category.Encrypt, "rotN_bruteforce", true, "rotN_bruteforce(String str)");
        addTag(Tag.Category.Encrypt, "rail_fence_encrypt", true,
               "rail_fence_encrypt(String message, int key)", "int", "4");
        addTag(Tag.Category.Decrypt, "rail_fence_decrypt", true,
               "rail_fence_decrypt(String encoded, int key)", "int", "4");
        addTag(Tag.Category.Encrypt, "substitution_encrypt", true,
               "substitution_encrypt(String message, String key)", "string", "phqgiumeaylnofdxjkrcvstzwb");
        addTag(Tag.Category.Decrypt, "substitution_decrypt", true,
               "substitution_decrypt(String ciphertext, String key)", "string", "phqgiumeaylnofdxjkrcvstzwb");
        addTag(Tag.Category.Encrypt, "is_like_english", true, "is_like_english(String str)");
        addTag(Tag.Category.Encrypt, "index_of_coincidence", true, "index_of_coincidence(String str)");
        addTag(Tag.Category.Encrypt, "guess_key_length", true, "guess_key_length(String ciphertext)");
    }

    private void initEncodingTags() {
        // Base encoding formats
        addTag(Tag.Category.Encode, "saml", true, "saml(String str)");
        addTag(Tag.Category.Encode, "base32", true, "base32_encode(String str)");
        addTag(Tag.Category.Encode, "base58", true, "base58Encode(String str)");
        addTag(Tag.Category.Encode, "base64", true, "base64Encode(String str)");
        addTag(Tag.Category.Encode, "base64url", true, "base64urlEncode(String str)");

        // HTML entities
        addTag(Tag.Category.Encode, "html_entities", true, "html_entities(String str)");
        addTag(Tag.Category.Encode, "html5_entities", true, "html5_entities(String str)");

        // Hex encoding with separator
        addTag(Tag.Category.Encode, "hex", true, "hex(String str, String separator)", "string", " ");

        // Various escape formats
        String[] escapeFormats = {
            "hex_entities", "hex_escapes", "octal_escapes", "dec_entities",
            "unicode_escapes", "css_escapes", "css_escapes6"
        };
        for (String format : escapeFormats) {
            String param = format.equals("css_escapes") ? "Bstr" : "str";
            addTag(Tag.Category.Encode, format, true, format + "(String " + param + ")");
        }

        // URL encoding variations
        String[] urlFormats = {"burp_urlencode", "urlencode", "urlencode_not_plus", "urlencode_all"};
        for (String format : urlFormats) {
            addTag(Tag.Category.Encode, format, true, format + "(String str)");
        }

        // PHP encoding
        addTag(Tag.Category.Encode, "php_non_alpha", true, "php_non_alpha(String input)");
        addTag(Tag.Category.Encode, "php_chr", true, "php_chr(String str)");
        addTag(Tag.Category.Encode, "sql_hex", true, "sql_hex(String str)");

        // JWT encoding
        addTag(Tag.Category.Encode, "jwt", true, "jwt(String payload, String algo, String secret)",
               "string", "HS256", "string", "secret");

        // Other encodings
        addTag(Tag.Category.Encode, "powershell", true, "powershell(String cmd)");
        addTag(Tag.Category.Encode, "quoted_printable", true, "quoted_printable(String str)");
        addTag(Tag.Category.Encode, "js_string", true, "js_string(String str)");
        addTag(Tag.Category.Encode, "unicode_alternatives", true, "unicode_alteratives(String str)");

        // UTF7 with exclude characters
        addTag(Tag.Category.Encode, "utf7", true, "utf7(String str, String excludeCharacters)",
               "string", "[\\s\\t\\r'(),-./:?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+!]");
    }

    private void initDecodingTags() {
        // SAML
        addTag(Tag.Category.Decode, "d_saml", true, "d_saml(String str)");

        // Auto decode
        addTag(Tag.Category.Decode, "auto_decode", true, "auto_decode(String str)");
        addTag(Tag.Category.Decode, "auto_decode_no_decrypt", true, "auto_decode_no_decrypt(String str)");

        // UTF7
        addTag(Tag.Category.Decode, "d_utf7", true, "utf7Decode(String str)");

        // Base encoding family
        addTag(Tag.Category.Decode, "d_base32", true, "decode_base32(String str)");
        addTag(Tag.Category.Decode, "d_base58", true, "decode_base58(String str)");
        addTag(Tag.Category.Decode, "d_base64", true, "decode_base64(String str)");
        addTag(Tag.Category.Decode, "d_base64url", true, "decode_base64url(String str)");

        // HTML entities
        addTag(Tag.Category.Decode, "d_html_entities", true, "decode_html_entities(String str)");
        addTag(Tag.Category.Decode, "d_html5_entities", true, "decode_html5_entities(String str)");

        // JavaScript and CSS
        addTag(Tag.Category.Decode, "d_js_string", true, "decode_js_string(String str)");
        addTag(Tag.Category.Decode, "d_css_escapes", true, "decode_css_escapes(String str)");

        // URL encoding
        addTag(Tag.Category.Decode, "d_burp_url", true, "burp_decode_url(String str)");
        addTag(Tag.Category.Decode, "d_url", true, "decode_url(String str)");

        // Escape sequences
        addTag(Tag.Category.Decode, "d_octal_escapes", true, "decode_octal_escapes(String str)");
        addTag(Tag.Category.Decode, "d_unicode_escapes", true, "decode_js_string(String str)");

        // JWT operations
        addTag(Tag.Category.Decode, "d_jwt_get_payload", true, "d_jwt_get_payload(String token)");
        addTag(Tag.Category.Decode, "d_jwt_get_header", true, "d_jwt_get_header(String token)");
        addTag(Tag.Category.Decode, "d_jwt_verify", true, "d_jwt_verify(String token, String secret)",
               "string", "secret");

        // Other decoding
        addTag(Tag.Category.Decode, "d_quoted_printable", true, "d_quoted_printable(String str)");
        addTag(Tag.Category.Decode, "json_parse", true, "json_parse(String json, String properties)",
               "string", "$property $propertyA-$propertyB");
    }

    private void initConditionTags() {
        addTag(Tag.Category.Conditions, "if_regex", true, "if_regex(String str, String regex, String value)",
               "string", "regex", "string", "value");
        addTag(Tag.Category.Conditions, "if_not_regex", true, "if_not_regex(String str, String regex, String value)",
               "string", "regex", "string", "value");
    }

    private void initConvertTags() {
        // Chunked conversion
        addTag(Tag.Category.Convert, "chunked_dec2hex", true, "chunked_dec2hex(String str)");

        // Decimal conversions
        addTag(Tag.Category.Convert, "dec2hex", true, "dec2hex(String str, String regex)",
               "string", "(\\d+)");
        addTag(Tag.Category.Convert, "dec2oct", true, "dec2oct(String str, String regex)",
               "string", "(\\d+)");
        addTag(Tag.Category.Convert, "dec2bin", true, "dec2bin(String str, String regex)",
               "string", "(\\d+)");

        // To decimal conversions
        addTag(Tag.Category.Convert, "hex2dec", true, "hex2dec(String str, String regex)",
               "string", "((?:0x)?[a-f0-9]+)");
        addTag(Tag.Category.Convert, "oct2dec", true, "oct2dec(String str, String regex)",
               "string", "([0-7]+)");
        addTag(Tag.Category.Convert, "bin2dec", true, "bin2dec(String str, String regex)",
               "string", "([0-1]+)");

        // ASCII conversions
        addTag(Tag.Category.Convert, "ascii2bin", true, "ascii2bin(String str)");
        addTag(Tag.Category.Convert, "bin2ascii", true, "bin2ascii(String str)");
        addTag(Tag.Category.Convert, "ascii2hex", true, "ascii2hex(String str, String separator)",
               "string", " ");
        addTag(Tag.Category.Convert, "hex2ascii", true, "hex2ascii(String str)");
        addTag(Tag.Category.Convert, "ascii2reverse_hex", true, "ascii2reverse_hex(String str, String separator)");
    }

    private void initStringTags() {
        // Case transformations
        addTag(Tag.Category.String, "uppercase", true, "uppercase(String str)");
        addTag(Tag.Category.String, "lowercase", true, "lowercase(String str)");
        addTag(Tag.Category.String, "capitalise", true, "capitalise(String str)");
        addTag(Tag.Category.String, "uncapitalise", true, "uncapitalise(String str)");

        // Character code operations
        addTag(Tag.Category.String, "from_charcode", true, "from_charcode(String str)");
        addTag(Tag.Category.String, "to_charcode", true, "to_charcode(String str)");

        // Basic string operations
        addTag(Tag.Category.String, "reverse", true, "reverse(String str)");
        addTag(Tag.Category.String, "length", true, "len(String str)");
        addTag(Tag.Category.String, "unique", true, "unique(String str)");
        addTag(Tag.Category.String, "space", false, "space()");
        addTag(Tag.Category.String, "newline", false, "newline()");

        // Search and replace
        addTag(Tag.Category.String, "find", true, "find(String str, String find, int group)",
               "string", "find", "int", "-1");
        addTag(Tag.Category.String, "replace", true, "replace(String str, String find, String replace)",
               "string", "find", "string", "replace");
        addTag(Tag.Category.String, "regex_replace", true, "regex_replace(String str, String find, String replace)",
               "string", "find", "string", "replace");

        // String manipulation
        addTag(Tag.Category.String, "repeat", true, "repeat(String str, int amount)",
               "int", "100");
        addTag(Tag.Category.String, "substring", true, "substring(String str, int start, int end)",
               "int", "0", "int", "100");
        addTag(Tag.Category.String, "split_join", true, "split_join(String str, String splitChar, String joinChar)",
               "string", "split char", "string", "join char");

        // Output control
        addTag(Tag.Category.String, "remove_output", true, "remove_output(String str)");
    }

    private void initHMACTags() {
        String[] hmacTypes = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"};
        for (String type : hmacTypes) {
            addTag(Tag.Category.HMAC, "hmac_" + type, true,
                   "hmac" + type + "(String str, String key)", "string", "SECRET");
        }
    }

    private void initHashTags() {
        // SHA family
        String[] shaTypes = {"sha1", "sha224", "sha256", "sha384", "sha512"};
        for (String type : shaTypes) {
            String param = type.equals("sha1") ? "str" : (type.equals("sha224") ? "message" : "str");
            addTag(Tag.Category.Hash, type, true, type + "(String " + param + ")");
        }

        // SHA3 family
        String[] sha3Types = {"sha3", "sha3_224", "sha3_256", "sha3_384", "sha3_512"};
        for (String type : sha3Types) {
            addTag(Tag.Category.Hash, type, true, type + "(String message)");
        }

        // Skein family
        String[] skeinTypes = {
            "skein_256_128", "skein_256_160", "skein_256_224", "skein_256_256",
            "skein_512_128", "skein_512_160", "skein_512_224", "skein_512_256",
            "skein_512_384", "skein_512_512", "skein_1024_384", "skein_1024_512", "skein_1024_1024"
        };
        for (String type : skeinTypes) {
            addTag(Tag.Category.Hash, type, true, type + "(String message)");
        }

        // Other hash algorithms
        addTag(Tag.Category.Hash, "sm3", true, "sm3(String message)");
        addTag(Tag.Category.Hash, "tiger", true, "tiger(String message)");
        addTag(Tag.Category.Hash, "md2", true, "md2(String str)");
        addTag(Tag.Category.Hash, "md4", true, "md4(String message)");
        addTag(Tag.Category.Hash, "md5", true, "md5(String str)");
        addTag(Tag.Category.Hash, "gost3411", true, "gost3411(String message)");

        // RIPEMD family
        String[] ripemdTypes = {"ripemd128", "ripemd160", "ripemd256", "ripemd320"};
        for (String type : ripemdTypes) {
            addTag(Tag.Category.Hash, type, true, type + "(String message)");
        }

        addTag(Tag.Category.Hash, "whirlpool", true, "whirlpool(String message)");
    }

    private void initMathTags() {
        // Range and arithmetic operations
        addTag(Tag.Category.Math, "range", true, "range(String str, int from, int to, int step)",
               "int", "0", "int", "100", "int", "1");
        addTag(Tag.Category.Math, "total", true, "total(String str)");
        addTag(Tag.Category.Math, "arithmetic", true, "arithmetic(String str, int amount, String operation, String splitChar)",
               "int", "10", "string", "+", "string", ",");
        addTag(Tag.Category.Math, "convert_base", true, "convert_base(String str, String splitChar, int from, int to)",
               "string", ",", "int", "from", "int", "to");

        // Random generation
        addTag(Tag.Category.Math, "random", true, "random(String chars, int len, Boolean everyCharOnce)",
               "int", "10", "boolean", "false");

        // Random alpha variants
        String[] randomTypes = {
            "random_alpha_lower", "random_alphanum_lower", "random_alpha_upper",
            "random_alphanum_upper", "random_alpha_mixed", "random_alphanum_mixed",
            "random_hex", "random_hex_mixed", "random_num"
        };
        for (String type : randomTypes) {
            addTag(Tag.Category.Math, type, false, type + "(int len)", "int", "10");
        }

        // Unicode random
        addTag(Tag.Category.Math, "random_unicode", false, "random_unicode(int from, int to, int amount)",
               "int", "0", "int", "0xffff", "int", "100");

        // Other math operations
        addTag(Tag.Category.Math, "zeropad", true, "zeropad(String str, String splitChar, int amount)",
               "string", ",", "int", "2");
        addTag(Tag.Category.Math, "uuid", false, "uuid()");
    }

    private void initXSSTags() {
        String[] xssTags = {
            "behavior", "css_expression", "datasrc", "eval_fromcharcode",
            "iframe_data_url", "iframe_src_doc", "script_data",
            "uppercase_script", "template_eval", "throw_eval"
        };
        for (String tagName : xssTags) {
            addTag(Tag.Category.XSS, tagName, true, tagName + "(String str)");
        }
    }

    private void initVariableTags() {
        // Variable management
        addTag(Tag.Category.Variables, "set_variable1", true,
               "Special tag that lets you store the results of a conversion. Change variable1 to your own variable name. The argument specifies if the variable is global.",
               "boolean", "false");

        addTag(Tag.Category.Variables, "increment_var", false,
               "increment_var(int start, String variableName, Boolean enabled)//This tag allows you to declare a variable and initialize it and then every subsequent conversion increments it.",
               "number", "0", "string", "variable", "boolean", "false");

        addTag(Tag.Category.Variables, "decrement_var", false,
               "decrement_var(int start, String variableName, Boolean enabled)//This tag allows you to declare a variable and initialize it and then every subsequent conversion decrements it.",
               "number", "0", "string", "variable", "boolean", "false");

        addTag(Tag.Category.Variables, "get_variable1", false,
               "Special tag that lets you get a previously set variable. Change var to your own variable name.");

        // Context operations
        addTag(Tag.Category.Variables, "context_request", false, "context_request(String codeExecuteKey)",
               "string", tagCodeExecutionKey);

        addTag(Tag.Category.Variables, "context_url", false, "context_url(String properties, String codeExecuteKey",
               "string", "$protocol $host $path $file $query $port", "string", tagCodeExecutionKey);

        addTag(Tag.Category.Variables, "context_body", false, "context_body(String codeExecuteKey)",
               "string", tagCodeExecutionKey);

        addTag(Tag.Category.Variables, "context_header", false, "context_url(String headerName, String codeExecuteKey",
               "string", "$headerName", "string", tagCodeExecutionKey);

        addTag(Tag.Category.Variables, "context_param", false, "context_url(String paramName, String codeExecuteKey",
               "string", "$paramName", "string", tagCodeExecutionKey);
    }

    private void initLanguageTags() {
        // Scripting languages
        addTag(Tag.Category.Languages, "python", true, "python(String input, String code, String codeExecuteKey)",
               "string", "output = input.upper()", "string", tagCodeExecutionKey);

        addTag(Tag.Category.Languages, "javascript", true, "javascript(String input, String code, String codeExecuteKey)",
               "string", "output = input.toUpperCase()", "string", tagCodeExecutionKey);

        addTag(Tag.Category.Languages, "java", true, "java(String input, String code, String codeExecuteKey)",
               "string", "output = input.toUpperCase()", "string", tagCodeExecutionKey);

        addTag(Tag.Category.Languages, "groovy", true, "groovy(String input, String code, String codeExecuteKey)",
               "string", "output = input.toUpperCase()", "string", tagCodeExecutionKey);

        // AI tag
        addTag(Tag.Category.Languages, "ai", true, "ai_tag(String input, String code, String codeExecuteKey)",
               "string", "1.0", "string", "Reverse this text", "string", tagCodeExecutionKey);
    }

    private void initSystemTags() {
        // URL reading
        addTag(Tag.Category.System, "read_url", true, "real_url(String url, String charset, String codeExecuteKey)",
               "string", "UTF-8", "boolean", "false", "string", tagCodeExecutionKey);

        // File operations
        addTag(Tag.Category.System, "read_file", true, "read_file(String filepath, String charset, Boolean enabled, String codeExecuteKey)",
               "string", "UTF-8", "boolean", "false", "string", tagCodeExecutionKey);

        // System commands
        addTag(Tag.Category.System, "system", true, "system(String cmd, Boolean enabled, String codeExecuteKey)",
               "boolean", "false", "string", tagCodeExecutionKey);
    }

    private void initCustomTags() {
        for (int j = 0; j < customTags.length(); j++) {
            JSONObject customTag = (JSONObject) customTags.get(j);
            Tag tag = CustomTags.generateCustomTag(customTag);
            tags.add(tag);
        }
    }

    public void generateFakeTags() {
        for (Map.Entry<String, List<String>> entry : FAKER_PROPERTIES.entrySet()) {
            String name = entry.getKey();
            List<String> properties = entry.getValue();
            Tag tag = new Tag(Tag.Category.Fake, "fake_" + name, false, name + "(String properties, String locale)");
            tag.argument1 = new TagArgument("string", String.join(", ", properties));
            tag.argument2 = new TagArgument("string", "en-GB");
            tags.add(tag);
        }
    }

    public static List<String> getFakerProperties(String fakerType) {
        return FAKER_PROPERTIES.get(fakerType);
    }

    public JSONArray getCustomTags() {
        return customTags;
    }

    public void setCustomTags(JSONArray tags) {
        this.customTags = tags;
    }

    public String convert(String message, Hackvertor hackvertor){
        return Convertors.weakConvert(new HashMap<>(), customTags, message, hackvertor);
    }

    public ArrayList<Tag> getTags() {
        ArrayList<Tag> tagsAndCustom = new ArrayList<>(tags);
        for (String variable : globalVariables.keySet()) {
            Tag variableTag = new Tag(Tag.Category.Globals, "get_" + variable, false, variable);
            tagsAndCustom.add(variableTag);
        }
        for (int j = 0; j < customTags.length(); j++) {
            JSONObject customTag = (JSONObject) customTags.get(j);
            Tag tag = CustomTags.generateCustomTag(customTag);
            tagsAndCustom.add(tag);
        }
        tagsAndCustom.sort(Comparator.comparing(o -> o.name));
        return tagsAndCustom;
    }
}
