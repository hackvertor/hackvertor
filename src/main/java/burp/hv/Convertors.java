package burp.hv;

import bsh.EvalError;
import bsh.Interpreter;
import burp.IParameter;
import burp.IRequestInfo;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.hv.ai.AI;
import burp.hv.settings.InvalidTypeSettingException;
import burp.hv.settings.UnregisteredSettingException;
import burp.hv.tags.CustomTags;
import burp.hv.tags.Tag;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.javafaker.Faker;
import groovy.lang.Binding;
import groovy.lang.GroovyShell;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.net.QuotedPrintableCodec;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;
import org.apache.commons.compress.compressors.deflate.DeflateParameters;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.util.encoders.Hex;
import org.brotli.dec.BrotliInputStream;
import org.codehaus.groovy.control.CompilationFailedException;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.HostAccess;
import org.json.JSONArray;
import org.json.JSONObject;
import org.python.core.PyException;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;
import org.unbescape.css.CssEscape;
import org.unbescape.css.CssStringEscapeLevel;
import org.unbescape.css.CssStringEscapeType;
import org.unbescape.html.HtmlEscape;
import org.unbescape.html.HtmlEscapeLevel;
import org.unbescape.html.HtmlEscapeType;
import org.unbescape.java.JavaEscape;
import org.unbescape.javascript.JavaScriptEscape;
import org.unbescape.javascript.JavaScriptEscapeLevel;
import org.unbescape.javascript.JavaScriptEscapeType;
import org.unbescape.json.JsonEscape;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.Normalizer;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.*;

import static burp.hv.HackvertorExtension.*;

public class Convertors {

    private Convertors(){}

    public static int calculateRealLen(String str) {
        int len = 0;
        for (int i = 0; i < str.length(); i++) {
            int cp = Character.codePointAt(str, i);
            if (cp <= 0x007F) {
                len++;
            } else if (cp <= 0x07FF) {
                len += 2;
            } else if (cp <= 0xFFFF) {
                len += 3;
            } else if (cp <= 0x10FFFF) {
                len += 4;
            }
        }
        return len;
    }

    public static String getString(ArrayList<String> args, Integer pos) {
        if (args.size() < pos + 1) {
            return "";
        }
        return JavaEscape.unescapeJava(args.get(pos));
    }

    public static Boolean getBoolean(ArrayList<String> args, Integer pos) {
        if (args.size() < pos + 1) {
            return false;
        }
        return Boolean.valueOf(args.get(pos));
    }

    public static Integer getInt(ArrayList<String> args, Integer pos) {
        Integer output;
        if (args.size() < pos + 1) {
            return 0;
        }
        if (args.get(pos).contains("0x")) {
            try {
                return Integer.parseInt(args.get(pos).replaceAll("^0x", ""), 16);
            } catch (NumberFormatException e) {
                throw new NumberFormatException(e.toString());
            }
        }
        try {
            output = Integer.parseInt(args.get(pos));
        } catch (NumberFormatException e) {
            stderr.println(e.getMessage());
            throw new NumberFormatException(e.toString());
        }
        return output;
    }

    private static void updateTagCount(String tag) {
        boolean allowTagCount;
        try {
            allowTagCount = generalSettings.getBoolean("allowTagCount");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            callbacks.printError("Error loading setting:" + e);
            throw new RuntimeException(e);
        }
        if(allowTagCount) {
            int count = tagCount.get(tag) == null ? 0 : tagCount.get(tag);
            tagCount.put(tag, count + 1);
        }
    }

    private static void processArguments(ArrayList<String> arguments, HashMap<String, String> variableMap,
                                        JSONArray customTags, Hackvertor hackvertor) throws ParseException {
        for(int i = 0; i < arguments.size(); i++) {
            arguments.set(i, weakConvert(variableMap, customTags, arguments.get(i), hackvertor));
        }
    }

    private static String processFakeTag(String tag, ArrayList<String> arguments) {
        return fake(tag, getString(arguments, 0), getString(arguments, 1));
    }

    private static String processCustomTag(String tag, String output, ArrayList<String> arguments,
                                          HashMap<String, String> variableMap, JSONArray customTags,
                                          Hackvertor hackvertor) throws ParseException {
        for (int i = 0; i < customTags.length(); i++) {
            JSONObject customTag = (JSONObject) customTags.get(i);
            String customTagName = customTag.getString("tagName");
            if(customTagName.equals(tag)) {
                return executeCustomTag(customTag, output, arguments, variableMap, customTags, hackvertor);
            }
        }
        return null;
    }

    private static String executeCustomTag(JSONObject customTag, String output, ArrayList<String> arguments,
                                          HashMap<String, String> variableMap, JSONArray customTags,
                                          Hackvertor hackvertor) throws ParseException {
        int numberOfArgs = customTag.has("numberOfArgs") ? customTag.getInt("numberOfArgs") : 0;
        String eKey;
        JSONObject customTagOptions = new JSONObject();
        customTagOptions.put("customTag", customTag);

        if (numberOfArgs == 0) {
            eKey = getString(arguments, 0);
            customTagOptions = null;
        } else if (numberOfArgs == 1) {
            processCustomTagArgument(customTagOptions, customTag, arguments, 0, "param1", "argument1Type");
            eKey = getString(arguments, 1);
        } else if (numberOfArgs == 2) {
            processCustomTagArgument(customTagOptions, customTag, arguments, 0, "param1", "argument1Type");
            processCustomTagArgument(customTagOptions, customTag, arguments, 1, "param2", "argument2Type");
            eKey = getString(arguments, 2);
        } else {
            eKey = getString(arguments, 0);
        }

        String language = customTag.getString("language").toLowerCase();
        String code = customTag.getString("code");

        switch (language) {
            case "ai":
                return ai_tag(variableMap, output, code, eKey, customTagOptions, customTags, hackvertor, 1.0, false);
            case "javascript":
                return javascript(variableMap, output, code, eKey, customTagOptions, customTags, hackvertor);
            case "python":
                return python(variableMap, output, code, eKey, customTagOptions, customTags, hackvertor);
            case "java":
                return java(variableMap, output, code, eKey, customTagOptions, customTags, hackvertor);
            case "groovy":
                return groovy(variableMap, output, code, eKey, customTagOptions, customTags, hackvertor);
            default:
                throw new ParseException("Unsupported language for custom tag: " + language);
        }
    }

    private static void processCustomTagArgument(JSONObject options, JSONObject customTag,
                                                ArrayList<String> arguments, int argIndex,
                                                String paramName, String typeKey) {
        String argType = customTag.getString(typeKey);
        if ("String".equals(argType)) {
            options.put(paramName, getString(arguments, argIndex));
        } else if ("Number".equals(argType)) {
            options.put(paramName, getInt(arguments, argIndex));
        }
    }

    private static String processLegacySetTag(String tag, String output, ArrayList<String> arguments,
                                             HashMap<String, String> variableMap) {
        String varname = tag.replace("set_", "");
        variableMap.put(varname, output);
        Boolean global = getBoolean(arguments, 0);
        if(global) {
            globalVariables.put(varname, output);
        }
        return output;
    }

    private static String processLegacyGetTag(String tag, String output, HashMap<String, String> variableMap) {
        String varname = tag.replace("get_", "");
        if(globalVariables.containsKey(varname) && !variableMap.containsKey(varname)) {
            return globalVariables.getOrDefault(varname, StringUtils.isEmpty(output) ? null : output);
        }
        return variableMap.getOrDefault(varname, StringUtils.isEmpty(output) ? null : output);
    }

    private static String handleUnsupportedTag(String tag, String output, ArrayList<String> arguments,
                                              HashMap<String, String> variableMap, JSONArray customTags) throws ParseException {
        try {
            return charset_convert(output, "UTF-8", tag);
        } catch (UnsupportedEncodingException e) {
            if(tag.matches(".*_\\d+$")) {
                String tagWithoutID = tag.replaceFirst("_\\d+$", "");
                try {
                    return callTag(variableMap, customTags, tagWithoutID, output, arguments, null);
                } catch (ParseException e1) {
                    // Fall through to throw unsupported tag error
                }
            }
            throw new ParseException("Unsupported Tag \"" + tag + "\"");
        }
    }

    @FunctionalInterface
    private interface TagProcessor {
        String process(String output, ArrayList<String> arguments, HashMap<String, String> variableMap,
                      JSONArray customTags, Hackvertor hackvertor) throws ParseException;
    }

    private static final Map<String, TagProcessor> TAG_REGISTRY = new HashMap<>();

    static {
        initializeTagRegistry();
    }

    private static void initializeTagRegistry() {
        // Variable operations
        TAG_REGISTRY.put("set", (output, args, vars, custom, hv) -> {
            vars.put(getString(args, 0), output);
            return output;
        });
        TAG_REGISTRY.put("set_var", TAG_REGISTRY.get("set"));
        TAG_REGISTRY.put("set_variable", TAG_REGISTRY.get("set"));

        TAG_REGISTRY.put("get", (output, args, vars, custom, hv) ->
            vars.getOrDefault(getString(args, 0), StringUtils.isEmpty(output) ? "UNDEFINED" : output));
        TAG_REGISTRY.put("get_var", TAG_REGISTRY.get("get"));
        TAG_REGISTRY.put("get_variable", TAG_REGISTRY.get("get"));

        TAG_REGISTRY.put("increment_var", (output, args, vars, custom, hv) ->
            increment_var(globalVariables, getInt(args, 0), getString(args, 1), getBoolean(args, 2)));
        TAG_REGISTRY.put("decrement_var", (output, args, vars, custom, hv) ->
            decrement_var(globalVariables, getInt(args, 0), getString(args, 1), getBoolean(args, 2)));

        // Context operations
        TAG_REGISTRY.put("context_request", (output, args, vars, custom, hv) ->
            context_request(getString(args, 0), hv));
        TAG_REGISTRY.put("context_url", (output, args, vars, custom, hv) ->
            context_url(getString(args, 0), getString(args, 1), hv));
        TAG_REGISTRY.put("context_header", (output, args, vars, custom, hv) ->
            context_header(getString(args, 0), getString(args, 1), hv));
        TAG_REGISTRY.put("context_body", (output, args, vars, custom, hv) ->
            context_body(getString(args, 0), hv));
        TAG_REGISTRY.put("context_param", (output, args, vars, custom, hv) ->
            context_param(getString(args, 0), getString(args, 1), hv));

        // Charset operations
        TAG_REGISTRY.put("charset_convert", (output, args, vars, custom, hv) -> {
            try {
                return charset_convert(output, getString(args, 0), getString(args, 1));
            } catch (UnsupportedEncodingException e) {
                throw new ParseException("Unsupported encoding \"" + e.getCause().getMessage() + "\"");
            }
        });

        // UTF-7 encoding
        TAG_REGISTRY.put("d_utf7", (output, args, vars, custom, hv) -> utf7Decode(output));
        TAG_REGISTRY.put("utf7", (output, args, vars, custom, hv) -> utf7(output, getString(args, 0)));

        // Compression operations
        TAG_REGISTRY.put("brotli_decompress", (output, args, vars, custom, hv) -> brotli_decompress(output));
        TAG_REGISTRY.put("gzip_compress", (output, args, vars, custom, hv) -> gzip_compress(output));
        TAG_REGISTRY.put("gzip_decompress", (output, args, vars, custom, hv) -> gzip_decompress(output));
        TAG_REGISTRY.put("bzip2_compress", (output, args, vars, custom, hv) -> bzip2_compress(output));
        TAG_REGISTRY.put("bzip2_decompress", (output, args, vars, custom, hv) -> bzip2_decompress(output));
        TAG_REGISTRY.put("deflate_compress", (output, args, vars, custom, hv) ->
            deflate_compress(output, getBoolean(args, 0)));
        TAG_REGISTRY.put("deflate_decompress", (output, args, vars, custom, hv) ->
            deflate_decompress(output, getBoolean(args, 0)));

        // SAML operations
        TAG_REGISTRY.put("saml", (output, args, vars, custom, hv) -> saml(output));
        TAG_REGISTRY.put("d_saml", (output, args, vars, custom, hv) -> d_saml(output));

        // Date/Time operations
        TAG_REGISTRY.put("timestamp", (output, args, vars, custom, hv) -> timestamp());
        TAG_REGISTRY.put("date", (output, args, vars, custom, hv) -> date(getString(args, 0), getString(args, 1)));

        // HTML entities
        TAG_REGISTRY.put("html_entities", (output, args, vars, custom, hv) -> html_entities(output));
        TAG_REGISTRY.put("d_html_entities", (output, args, vars, custom, hv) -> decode_html_entities(output));
        TAG_REGISTRY.put("html5_entities", (output, args, vars, custom, hv) -> html5_entities(output));
        TAG_REGISTRY.put("d_html5_entities", (output, args, vars, custom, hv) -> decode_html5_entities(output));

        // Hex operations
        TAG_REGISTRY.put("hex", (output, args, vars, custom, hv) -> hex(output, getString(args, 0)));
        TAG_REGISTRY.put("hex_entities", (output, args, vars, custom, hv) -> hex_entities(output));
        TAG_REGISTRY.put("hex_escapes", (output, args, vars, custom, hv) -> hex_escapes(output));

        // Escaping operations
        TAG_REGISTRY.put("octal_escapes", (output, args, vars, custom, hv) -> octal_escapes(output));
        TAG_REGISTRY.put("d_octal_escapes", (output, args, vars, custom, hv) -> decode_octal_escapes(output));
        TAG_REGISTRY.put("css_escapes", (output, args, vars, custom, hv) -> css_escapes(output));
        TAG_REGISTRY.put("css_escapes6", (output, args, vars, custom, hv) -> css_escapes6(output));
        TAG_REGISTRY.put("d_css_escapes", (output, args, vars, custom, hv) -> decode_css_escapes(output));
        TAG_REGISTRY.put("dec_entities", (output, args, vars, custom, hv) -> dec_entities(output));
        TAG_REGISTRY.put("unicode_escapes", (output, args, vars, custom, hv) -> unicode_escapes(output));
        TAG_REGISTRY.put("d_unicode_escapes", (output, args, vars, custom, hv) -> decode_js_string(output));
        TAG_REGISTRY.put("unicode_alternatives", (output, args, vars, custom, hv) -> unicode_alternatives(output));

        // PHP operations
        TAG_REGISTRY.put("php_non_alpha", (output, args, vars, custom, hv) -> php_non_alpha(output));
        TAG_REGISTRY.put("php_chr", (output, args, vars, custom, hv) -> php_chr(output));
        TAG_REGISTRY.put("sql_hex", (output, args, vars, custom, hv) -> sql_hex(output));

        // Classical ciphers
        TAG_REGISTRY.put("rotN", (output, args, vars, custom, hv) -> rotN(output, getInt(args, 0)));
        TAG_REGISTRY.put("rotN_bruteforce", (output, args, vars, custom, hv) -> rotN_bruteforce(output));
        TAG_REGISTRY.put("xor", (output, args, vars, custom, hv) -> xor(output, getString(args, 0)));
        TAG_REGISTRY.put("xor_decrypt", (output, args, vars, custom, hv) -> xor_decrypt(output, getInt(args, 0), false));
        TAG_REGISTRY.put("xor_getkey", (output, args, vars, custom, hv) -> xor_getkey(output));
        TAG_REGISTRY.put("affine_encrypt", (output, args, vars, custom, hv) ->
            affine_encrypt(output, getInt(args, 0), getInt(args, 1)));
        TAG_REGISTRY.put("affine_decrypt", (output, args, vars, custom, hv) ->
            affine_decrypt(output, getInt(args, 0), getInt(args, 1)));
        TAG_REGISTRY.put("atbash_encrypt", (output, args, vars, custom, hv) -> atbash_encrypt(output));
        TAG_REGISTRY.put("atbash_decrypt", (output, args, vars, custom, hv) -> atbash_decrypt(output));
        TAG_REGISTRY.put("rail_fence_encrypt", (output, args, vars, custom, hv) ->
            rail_fence_encrypt(output, getInt(args, 0)));
        TAG_REGISTRY.put("rail_fence_decrypt", (output, args, vars, custom, hv) ->
            rail_fence_decrypt(output, getInt(args, 0)));
        TAG_REGISTRY.put("substitution_encrypt", (output, args, vars, custom, hv) ->
            substitution_encrypt(output, getString(args, 0)));
        TAG_REGISTRY.put("substitution_decrypt", (output, args, vars, custom, hv) ->
            substitution_decrypt(output, getString(args, 0)));

        // AES operations
        TAG_REGISTRY.put("aes_encrypt", (output, args, vars, custom, hv) ->
            aes_encrypt(output, getString(args, 0), getString(args, 1), getString(args, 2)));
        TAG_REGISTRY.put("aes_decrypt", (output, args, vars, custom, hv) ->
            aes_decrypt(output, getString(args, 0), getString(args, 1), getString(args, 2)));

        // JWT operations
        TAG_REGISTRY.put("jwt", (output, args, vars, custom, hv) ->
            jwt(output, getString(args, 0), getString(args, 1)));
        TAG_REGISTRY.put("d_jwt_get_payload", (output, args, vars, custom, hv) -> d_jwt_get_payload(output));
        TAG_REGISTRY.put("d_jwt_get_header", (output, args, vars, custom, hv) -> d_jwt_get_header(output));
        TAG_REGISTRY.put("d_jwt_verify", (output, args, vars, custom, hv) ->
            d_jwt_verify(output, getString(args, 0)));

        // String encoding operations
        TAG_REGISTRY.put("quoted_printable", (output, args, vars, custom, hv) -> quoted_printable(output));
        TAG_REGISTRY.put("d_quoted_printable", (output, args, vars, custom, hv) -> d_quoted_printable(output));
        TAG_REGISTRY.put("powershell", (output, args, vars, custom, hv) -> powershell(output));
        TAG_REGISTRY.put("js_string", (output, args, vars, custom, hv) -> js_string(output));
        TAG_REGISTRY.put("d_js_string", (output, args, vars, custom, hv) -> decode_js_string(output));

        // Auto decode operations
        TAG_REGISTRY.put("auto_decode", (output, args, vars, custom, hv) -> auto_decode(output));
        TAG_REGISTRY.put("auto_decode_no_decrypt", (output, args, vars, custom, hv) -> auto_decode_no_decrypt(output));

        // Base encoding operations
        TAG_REGISTRY.put("base32", (output, args, vars, custom, hv) -> base32_encode(output));
        TAG_REGISTRY.put("d_base32", (output, args, vars, custom, hv) -> decode_base32(output));
        TAG_REGISTRY.put("base58", (output, args, vars, custom, hv) -> base58_encode(output));
        TAG_REGISTRY.put("d_base58", (output, args, vars, custom, hv) -> decode_base58(output));
        TAG_REGISTRY.put("base64", (output, args, vars, custom, hv) -> base64Encode(output));
        TAG_REGISTRY.put("d_base64", (output, args, vars, custom, hv) -> decode_base64(output));
        TAG_REGISTRY.put("base64url", (output, args, vars, custom, hv) -> base64urlEncode(output));
        TAG_REGISTRY.put("d_base64url", (output, args, vars, custom, hv) -> decode_base64url(output));

        // JSON operations
        TAG_REGISTRY.put("json_parse", (output, args, vars, custom, hv) ->
            json_parse(output, getString(args, 0)));

        // URL encoding operations
        TAG_REGISTRY.put("burp_urlencode", (output, args, vars, custom, hv) -> burp_urlencode(output));
        TAG_REGISTRY.put("urlencode", (output, args, vars, custom, hv) -> urlencode(output));
        TAG_REGISTRY.put("urlencode_not_plus", (output, args, vars, custom, hv) -> urlencode_not_plus(output));
        TAG_REGISTRY.put("urlencode_all", (output, args, vars, custom, hv) -> urlencode_all(output));
        TAG_REGISTRY.put("d_burp_url", (output, args, vars, custom, hv) -> burp_decode_url(output));
        TAG_REGISTRY.put("d_url", (output, args, vars, custom, hv) -> decode_url(output));

        // String operations
        TAG_REGISTRY.put("uppercase", (output, args, vars, custom, hv) -> uppercase(output));
        TAG_REGISTRY.put("lowercase", (output, args, vars, custom, hv) -> lowercase(output));
        TAG_REGISTRY.put("capitalise", (output, args, vars, custom, hv) -> capitalise(output));
        TAG_REGISTRY.put("uncapitalise", (output, args, vars, custom, hv) -> uncapitalise(output));
        TAG_REGISTRY.put("reverse", (output, args, vars, custom, hv) -> reverse(output));
        TAG_REGISTRY.put("unique", (output, args, vars, custom, hv) -> unique(output));
        TAG_REGISTRY.put("space", (output, args, vars, custom, hv) -> " ");
        TAG_REGISTRY.put("newline", (output, args, vars, custom, hv) -> "\n");
        TAG_REGISTRY.put("remove_output", (output, args, vars, custom, hv) -> remove_output(output));
        TAG_REGISTRY.put("from_charcode", (output, args, vars, custom, hv) -> from_charcode(output));
        TAG_REGISTRY.put("to_charcode", (output, args, vars, custom, hv) -> to_charcode(output));
        TAG_REGISTRY.put("length", (output, args, vars, custom, hv) -> len(output));

        // String search and replace
        TAG_REGISTRY.put("find", (output, args, vars, custom, hv) ->
            find(output, getString(args, 0), getInt(args, 1)));
        TAG_REGISTRY.put("replace", (output, args, vars, custom, hv) ->
            replace(output, getString(args, 0), getString(args, 1)));
        TAG_REGISTRY.put("regex_replace", (output, args, vars, custom, hv) ->
            regex_replace(output, getString(args, 0), getString(args, 1)));
        TAG_REGISTRY.put("repeat", (output, args, vars, custom, hv) -> repeat(output, getInt(args, 0)));
        TAG_REGISTRY.put("substring", (output, args, vars, custom, hv) ->
            substring(output, getInt(args, 0), getInt(args, 1)));
        TAG_REGISTRY.put("split_join", (output, args, vars, custom, hv) ->
            split_join(output, getString(args, 0), getString(args, 1)));

        // Analysis operations
        TAG_REGISTRY.put("is_like_english", (output, args, vars, custom, hv) ->
            Double.toString(is_like_english(output)));
        TAG_REGISTRY.put("index_of_coincidence", (output, args, vars, custom, hv) ->
            Double.toString(index_of_coincidence(output)));
        TAG_REGISTRY.put("guess_key_length", (output, args, vars, custom, hv) ->
            Integer.toString(guess_key_length(output)));

        // Conditional operations
        TAG_REGISTRY.put("if_regex", (output, args, vars, custom, hv) ->
            if_regex(output, getString(args, 0), getString(args, 1)));
        TAG_REGISTRY.put("if_not_regex", (output, args, vars, custom, hv) ->
            if_not_regex(output, getString(args, 0), getString(args, 1)));

        // Number conversion operations
        TAG_REGISTRY.put("chunked_dec2hex", (output, args, vars, custom, hv) -> chunked_dec2hex(output));
        TAG_REGISTRY.put("dec2hex", (output, args, vars, custom, hv) -> dec2hex(output, getString(args, 0)));
        TAG_REGISTRY.put("dec2oct", (output, args, vars, custom, hv) -> dec2oct(output, getString(args, 0)));
        TAG_REGISTRY.put("dec2bin", (output, args, vars, custom, hv) -> dec2bin(output, getString(args, 0)));
        TAG_REGISTRY.put("hex2dec", (output, args, vars, custom, hv) -> hex2dec(output, getString(args, 0)));
        TAG_REGISTRY.put("oct2dec", (output, args, vars, custom, hv) -> oct2dec(output, getString(args, 0)));
        TAG_REGISTRY.put("bin2dec", (output, args, vars, custom, hv) -> bin2dec(output, getString(args, 0)));
        TAG_REGISTRY.put("ascii2bin", (output, args, vars, custom, hv) -> ascii2bin(output));
        TAG_REGISTRY.put("bin2ascii", (output, args, vars, custom, hv) -> bin2ascii(output));
        TAG_REGISTRY.put("hex2ascii", (output, args, vars, custom, hv) -> hex2ascii(output));
        TAG_REGISTRY.put("ascii2hex", (output, args, vars, custom, hv) -> ascii2hex(output, getString(args, 0)));
        TAG_REGISTRY.put("ascii2reverse_hex", (output, args, vars, custom, hv) ->
            ascii2reverse_hex(output, getString(args, 0)));

        // HMAC operations
        TAG_REGISTRY.put("hmac_md5", (output, args, vars, custom, hv) -> hmacmd5(output, getString(args, 0)));
        TAG_REGISTRY.put("hmac_sha1", (output, args, vars, custom, hv) -> hmacsha1(output, getString(args, 0)));
        TAG_REGISTRY.put("hmac_sha224", (output, args, vars, custom, hv) -> hmacsha224(output, getString(args, 0)));
        TAG_REGISTRY.put("hmac_sha256", (output, args, vars, custom, hv) -> hmacsha256(output, getString(args, 0)));
        TAG_REGISTRY.put("hmac_sha384", (output, args, vars, custom, hv) -> hmacsha384(output, getString(args, 0)));
        TAG_REGISTRY.put("hmac_sha512", (output, args, vars, custom, hv) -> hmacsha512(output, getString(args, 0)));

        // Hash operations
        TAG_REGISTRY.put("sha1", (output, args, vars, custom, hv) -> sha1(output));
        TAG_REGISTRY.put("sha224", (output, args, vars, custom, hv) -> sha224(output));
        TAG_REGISTRY.put("sha256", (output, args, vars, custom, hv) -> sha256(output));
        TAG_REGISTRY.put("sha384", (output, args, vars, custom, hv) -> sha384(output));
        TAG_REGISTRY.put("sha512", (output, args, vars, custom, hv) -> sha512(output));
        TAG_REGISTRY.put("sha3", (output, args, vars, custom, hv) -> sha3(output));
        TAG_REGISTRY.put("sha3_224", (output, args, vars, custom, hv) -> sha3_224(output));
        TAG_REGISTRY.put("sha3_256", (output, args, vars, custom, hv) -> sha3_256(output));
        TAG_REGISTRY.put("sha3_384", (output, args, vars, custom, hv) -> sha3_384(output));
        TAG_REGISTRY.put("sha3_512", (output, args, vars, custom, hv) -> sha3_512(output));
        TAG_REGISTRY.put("md2", (output, args, vars, custom, hv) -> md2(output));
        TAG_REGISTRY.put("md4", (output, args, vars, custom, hv) -> md4(output));
        TAG_REGISTRY.put("md5", (output, args, vars, custom, hv) -> md5(output));
        TAG_REGISTRY.put("tiger", (output, args, vars, custom, hv) -> tiger(output));
        TAG_REGISTRY.put("whirlpool", (output, args, vars, custom, hv) -> whirlpool(output));
        TAG_REGISTRY.put("gost3411", (output, args, vars, custom, hv) -> gost3411(output));
        TAG_REGISTRY.put("sm3", (output, args, vars, custom, hv) -> sm3(output));
        TAG_REGISTRY.put("ripemd128", (output, args, vars, custom, hv) -> ripemd128(output));
        TAG_REGISTRY.put("ripemd160", (output, args, vars, custom, hv) -> ripemd160(output));
        TAG_REGISTRY.put("ripemd256", (output, args, vars, custom, hv) -> ripemd256(output));
        TAG_REGISTRY.put("ripemd320", (output, args, vars, custom, hv) -> ripemd320(output));

        // Skein hash operations
        TAG_REGISTRY.put("skein_256_128", (output, args, vars, custom, hv) -> skein_256_128(output));
        TAG_REGISTRY.put("skein_256_160", (output, args, vars, custom, hv) -> skein_256_160(output));
        TAG_REGISTRY.put("skein_256_224", (output, args, vars, custom, hv) -> skein_256_224(output));
        TAG_REGISTRY.put("skein_256_256", (output, args, vars, custom, hv) -> skein_256_256(output));
        TAG_REGISTRY.put("skein_512_128", (output, args, vars, custom, hv) -> skein_512_128(output));
        TAG_REGISTRY.put("skein_512_160", (output, args, vars, custom, hv) -> skein_512_160(output));
        TAG_REGISTRY.put("skein_512_224", (output, args, vars, custom, hv) -> skein_512_224(output));
        TAG_REGISTRY.put("skein_512_256", (output, args, vars, custom, hv) -> skein_512_256(output));
        TAG_REGISTRY.put("skein_512_384", (output, args, vars, custom, hv) -> skein_512_384(output));
        TAG_REGISTRY.put("skein_512_512", (output, args, vars, custom, hv) -> skein_512_512(output));
        TAG_REGISTRY.put("skein_1024_384", (output, args, vars, custom, hv) -> skein_1024_384(output));
        TAG_REGISTRY.put("skein_1024_512", (output, args, vars, custom, hv) -> skein_1024_512(output));
        TAG_REGISTRY.put("skein_1024_1024", (output, args, vars, custom, hv) -> skein_1024_1024(output));

        // Random operations
        TAG_REGISTRY.put("random", (output, args, vars, custom, hv) ->
            random(output, getInt(args, 0), getBoolean(args, 1)));
        TAG_REGISTRY.put("random_alpha_lower", (output, args, vars, custom, hv) ->
            random_alpha_lower(getInt(args, 0)));
        TAG_REGISTRY.put("random_alphanum_lower", (output, args, vars, custom, hv) ->
            random_alphanum_lower(getInt(args, 0)));
        TAG_REGISTRY.put("random_alpha_upper", (output, args, vars, custom, hv) ->
            random_alpha_upper(getInt(args, 0)));
        TAG_REGISTRY.put("random_alphanum_upper", (output, args, vars, custom, hv) ->
            random_alphanum_upper(getInt(args, 0)));
        TAG_REGISTRY.put("random_alpha_mixed", (output, args, vars, custom, hv) ->
            random_alpha_mixed(getInt(args, 0)));
        TAG_REGISTRY.put("random_alphanum_mixed", (output, args, vars, custom, hv) ->
            random_alphanum_mixed(getInt(args, 0)));
        TAG_REGISTRY.put("random_hex", (output, args, vars, custom, hv) -> random_hex(getInt(args, 0)));
        TAG_REGISTRY.put("random_hex_mixed", (output, args, vars, custom, hv) ->
            random_hex_mixed(getInt(args, 0)));
        TAG_REGISTRY.put("random_num", (output, args, vars, custom, hv) -> random_num(getInt(args, 0)));
        TAG_REGISTRY.put("random_unicode", (output, args, vars, custom, hv) ->
            random_unicode(getInt(args, 0), getInt(args, 1), getInt(args, 2)));

        // Math operations
        TAG_REGISTRY.put("range", (output, args, vars, custom, hv) ->
            range(output, getInt(args, 0), getInt(args, 1), getInt(args, 2)));
        TAG_REGISTRY.put("total", (output, args, vars, custom, hv) -> total(output));
        TAG_REGISTRY.put("arithmetic", (output, args, vars, custom, hv) ->
            arithmetic(output, getInt(args, 0), getString(args, 1), getString(args, 2)));
        TAG_REGISTRY.put("convert_base", (output, args, vars, custom, hv) ->
            convert_base(output, getString(args, 0), getInt(args, 1), getInt(args, 2)));
        TAG_REGISTRY.put("zeropad", (output, args, vars, custom, hv) ->
            zeropad(output, getString(args, 0), getInt(args, 1)));
        TAG_REGISTRY.put("uuid", (output, args, vars, custom, hv) -> uuid());

        // XSS payload operations
        TAG_REGISTRY.put("behavior", (output, args, vars, custom, hv) -> behavior(output));
        TAG_REGISTRY.put("css_expression", (output, args, vars, custom, hv) -> css_expression(output));
        TAG_REGISTRY.put("datasrc", (output, args, vars, custom, hv) -> datasrc(output));
        TAG_REGISTRY.put("eval_fromcharcode", (output, args, vars, custom, hv) -> eval_fromcharcode(output));
        TAG_REGISTRY.put("iframe_data_url", (output, args, vars, custom, hv) -> iframe_data_url(output));
        TAG_REGISTRY.put("script_data", (output, args, vars, custom, hv) -> script_data(output));
        TAG_REGISTRY.put("uppercase_script", (output, args, vars, custom, hv) -> uppercase_script(output));
        TAG_REGISTRY.put("iframe_src_doc", (output, args, vars, custom, hv) -> iframe_src_doc(output));
        TAG_REGISTRY.put("template_eval", (output, args, vars, custom, hv) -> template_eval(output));
        TAG_REGISTRY.put("throw_eval", (output, args, vars, custom, hv) -> throw_eval(output));

        // Script execution operations
        TAG_REGISTRY.put("python", (output, args, vars, custom, hv) ->
            python(vars, output, getString(args, 0), getString(args, 1), null, custom, hv));
        TAG_REGISTRY.put("javascript", (output, args, vars, custom, hv) ->
            javascript(vars, output, getString(args, 0), getString(args, 1), null, custom, hv));
        TAG_REGISTRY.put("java", (output, args, vars, custom, hv) ->
            java(vars, output, getString(args, 0), getString(args, 1), null, custom, hv));
        TAG_REGISTRY.put("groovy", (output, args, vars, custom, hv) ->
            groovy(vars, output, getString(args, 0), getString(args, 1), null, custom, hv));
        TAG_REGISTRY.put("ai", (output, args, vars, custom, hv) ->
            ai_tag(vars, output, getString(args, 1), getString(args, 2), null, custom, hv,
                   Double.parseDouble(getString(args, 0)), false));

        // System operations
        TAG_REGISTRY.put("read_url", (output, args, vars, custom, hv) ->
            read_url(output, getString(args, 0), getBoolean(args, 1), getString(args, 2)));
        TAG_REGISTRY.put("read_file", (output, args, vars, custom, hv) ->
            read_file(output, getString(args, 0), getBoolean(args, 1), getString(args, 2)));
        TAG_REGISTRY.put("system", (output, args, vars, custom, hv) ->
            system(output, getBoolean(args, 0), getString(args, 1)));
    }

    public static String callTag(HashMap<String, String> variableMap, JSONArray customTags, String tag, String output, ArrayList<String> arguments, Hackvertor hackvertor) throws ParseException {
        // Update tag count if enabled
        updateTagCount(tag);

        // Process arguments recursively
        processArguments(arguments, variableMap, customTags, hackvertor);

        // First check if the tag is in the registry
        TagProcessor processor = TAG_REGISTRY.get(tag);
        if (processor != null) {
            return processor.process(output, arguments, variableMap, customTags, hackvertor);
        }

        // Handle special case tags that are not in the registry
        // Handle fake_ tags
        if (tag.startsWith("fake_")) {
            return processFakeTag(tag, arguments);
        }
        // Handle custom tags (starting with _)
        else if (tag.startsWith("_")) {
            String result = processCustomTag(tag, output, arguments, variableMap, customTags, hackvertor);
            if (result != null) {
                return result;
            }
        }
        // Handle legacy set_ tags (but not set_var or set_variable which are in the registry)
        else if(tag.startsWith("set_")) {
            return processLegacySetTag(tag, output, arguments, variableMap);
        }
        // Handle legacy get_ tags (but not get_var or get_variable which are in the registry)
        else if(tag.startsWith("get_")) {
            return processLegacyGetTag(tag, output, variableMap);
        }

        // Handle unsupported tags or charset conversion fallback
        return handleUnsupportedTag(tag, output, arguments, variableMap, customTags);
    }

    public static String[] generateTagStartEnd(Tag tagObj) {
        String[] tag = new String[2];
        ArrayList<String> args = new ArrayList<>();
        if(tagObj.argument1 != null) args.add(tagObj.argument1.value);
        if(tagObj.argument2 != null) args.add(tagObj.argument2.value);
        if(tagObj.argument3 != null) args.add(tagObj.argument3.value);
        if(tagObj.argument4 != null) args.add(tagObj.argument4.value);

        if (tagObj.hasInput) {
            tag[0] = new Element.StartTag(tagObj.name, args).toString();
            tag[1] = new Element.EndTag(tagObj.name).toString();
        } else {
            tag[0] = new Element.SelfClosingTag(tagObj.name, args).toString();
            tag[1] = "";
        }
        return tag;
    }

    /**
     * Recursive conversion, ensuring tags are properly matched.
     * Does not treat mismatched tags as text.
     */
    public static String strictConvert(HashMap<String, String> variables, JSONArray customTags, String input, Hackvertor hackvertor){
        Queue<Element> tagElements;
        try {
            tagElements = HackvertorParser.parse(input);
            return strictConvert(variables, customTags, "", new Stack<>(), tagElements, hackvertor);
        }catch (Exception e){
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return String.format("Error: %s\n%s", e.getMessage(), sw);
        }
    }

    /**
     * Recursive conversion, treating mismatched tags as text
     */
    public static String weakConvert(HashMap<String, String> variables, JSONArray customTags, String input, Hackvertor hackvertor){
        Queue<Element> tagElements;
        try {
            tagElements = HackvertorParser.parse(input);
            tagElements = weakConvertPreProcessSetTags(variables, customTags, tagElements);
            return weakConvert(variables, customTags, new Stack<>(), tagElements, hackvertor);
        }catch (Exception e){
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return String.format("Error: %s\n%s", e.getMessage(), sw);
        }
    }

    /**
     * Recursive conversion, ensuring tags are properly matched.
     * Does not treat mismatched tags as text. Will throw an error instead.
     * @param variables
     * @param customTags
     * @param textBuffer
     * @param stack
     * @param elements
     * @return
     * @throws ParseException
     */
    private static String strictConvert(HashMap<String, String> variables,
                                        JSONArray customTags,
                                        String textBuffer,
                                        Stack<Element.StartTag> stack,
                                        Queue<Element> elements, Hackvertor hackvertor) throws ParseException{
        if(elements.size() == 0) {
            if(stack.size() > 0){
                String error = String.format("Unclosed tag%s - %s",stack.size()>1?"s":"",
                        stack.stream().map(Element.StartTag::getIdentifier).collect(Collectors.joining()));
                throw new ParseException(error);
            }
            return textBuffer;
        }

        //Take the first item from the queue.
        Element element = elements.remove();
        if(element instanceof Element.TextElement){ //Text element, add it to our textBuffer
            textBuffer+= ((Element.TextElement) element).getContent();
        }else if(element instanceof Element.SelfClosingTag){ //Self closing tag. Just add its output to textbuffer.
            Element.SelfClosingTag selfClosingTag = (Element.SelfClosingTag) element;
            String tagOutput = callTag(variables, customTags, selfClosingTag.getIdentifier(), "", selfClosingTag.getArguments(), hackvertor);
            textBuffer+= tagOutput;
        }else if(element instanceof Element.StartTag){ //Start of a conversion.
            stack.push((Element.StartTag) element);
            textBuffer+= strictConvert(variables, customTags, "", stack, elements, hackvertor);
        }else if(element instanceof Element.EndTag){ //End of a conversion. Convert and update textbuffer.
            Element.StartTag startTag;
            Element.EndTag endTag = (Element.EndTag) element;
            try {
                startTag = stack.pop();
            }catch (EmptyStackException e){
                throw new ParseException(String.format("Found closing tag \"%s\" without matching open tag.", endTag.getIdentifier()));
            }
            if(!startTag.getIdentifier().equalsIgnoreCase(endTag.getIdentifier())){ //Check stack matches end tag.
                throw new ParseException(String.format("Mismatched opening and closing tags, %s and %s.",
                        startTag.getIdentifier(), endTag.getIdentifier()));
            }
            return callTag(variables, customTags, startTag.getIdentifier(), textBuffer, startTag.getArguments(), hackvertor);
        }

        return strictConvert(variables, customTags, textBuffer, stack, elements, hackvertor);
    }

    /**
     * Process all variable setting tags in a list of tokens, and update the variables map with their values
     * @param variables The map of variables and their values
     * @param customTags Any custom tags to be processed
     * @param elements A list of lexical tokens
     * @return
     * @throws ParseException
     */
    private static Queue<Element> weakConvertPreProcessSetTags(HashMap<String, String> variables,
                                                               JSONArray customTags,
                                                               Queue<Element> elements) throws ParseException{
        Queue<Element> elementQueue = new LinkedList<>();
        Iterator<Element> iter = elements.iterator();
        while(iter.hasNext()) {
            Element element = iter.next();
            if (element instanceof Element.StartTag) {
                Element.StartTag startSetTag = (Element.StartTag) element;
                if (startSetTag.getIdentifier().equalsIgnoreCase("set")
                        || startSetTag.getIdentifier().startsWith("set_")) {
                    //We're processing the contents of a set tag.
                    Queue<Element> setQueue = new LinkedList<>();
                    setQueue.add(startSetTag);
                    while (iter.hasNext()){
                        element = iter.next();
                        setQueue.add(element);
                        if(element instanceof Element.EndTag &&
                                ((Element.EndTag) element).getIdentifier().equalsIgnoreCase(startSetTag.getIdentifier())){
                            //We've got the matching end tag.
                            String output = weakConvert(variables, customTags, new Stack<>(), setQueue, null);
                            setQueue.clear();
                            elementQueue.add(new Element.TextElement(output));
                            break;
                        }
                    }
                    if(!setQueue.isEmpty()){ //If we didn't find the matching close tag.
                        elementQueue.add(startSetTag);
                        elementQueue.addAll(setQueue);
                    }
                }else{
                    elementQueue.add(element);
                }
            }else{
                elementQueue.add(element);
            }
        }
        return elementQueue;
    }

    /**
     * @param variables
     * @param customTags
     * @param stack
     * @param elements
     * @param hackvertor
     * @return
     * @throws ParseException
     */
    private static String weakConvert(HashMap<String, String> variables,
                                      JSONArray customTags,
                                      Stack<Element> stack,
                                      Queue<Element> elements, Hackvertor hackvertor) throws ParseException{

        if(elements.size() == 0) {
            StringBuilder sb = new StringBuilder();
            while(!stack.empty()){
                sb.insert(0, stack.pop());
            }
            return sb.toString();
        }

        //Take the first item from the queue.
        Element element = elements.remove();
        if(element instanceof Element.TextElement){ //Text element, add it to our stack
            stack.push((element));
        }else if(element instanceof Element.SelfClosingTag){ //Self closing tag. Add its output as a TextElement to our stack.
            Element.SelfClosingTag selfClosingTag = (Element.SelfClosingTag) element;
            String tagOutput = callTag(variables, customTags, selfClosingTag.getIdentifier(), "", selfClosingTag.getArguments(), hackvertor);
            stack.push(new Element.TextElement(tagOutput));
        }else if(element instanceof Element.StartTag){ //Start of a conversion.
            Stack<Element> newStackContext = new Stack<>();
            newStackContext.push(element);
            stack.push(new Element.TextElement(weakConvert(variables, customTags, newStackContext, elements, hackvertor)));
        }else if(element instanceof Element.EndTag){ //End of a conversion. Convert and update textbuffer.
            Stack<Element> siftStack = new Stack<>();

            try {
                Element startTag = stack.pop();
                Element.EndTag endTag = (Element.EndTag) element;

                //Look through our stack until we find the matching opening tag, and add interim items to a processing stack
                while (!(startTag instanceof Element.StartTag) || !((Element.StartTag) startTag).getIdentifier().equalsIgnoreCase(endTag.getIdentifier())){
                    siftStack.push(startTag);
                    startTag = stack.pop();
                }
                //We found the matching start tag!
                //All the items on the sift stack should be treated as text, so add them to the text buffer.
                StringBuilder sb = new StringBuilder();
                while(!siftStack.empty()){
                    sb.append(siftStack.pop());
                }

                //Now we've matched the tag, convert the textbuffer contents.
                return callTag(variables, customTags, ((Element.StartTag) startTag).getIdentifier(), sb.toString(), ((Element.StartTag) startTag).getArguments(), hackvertor);
            }catch (EmptyStackException ex){
                //Looked through the whole stack and didn't find a matching open tag. Must be a rogue close tag instead.
                //In this case, add items we removed, and the textual representation of the close tag, back to the stack.
                while(!siftStack.empty()){
                    stack.push(siftStack.pop());
                }
                stack.add(new Element.TextElement(element.toString()));
            }
        }

        return weakConvert(variables, customTags, stack, elements, hackvertor);
    }


    static String convertCharset(String input, String to) {
        String output = "";
        try {
            return helpers.bytesToString(input.getBytes(to));
        } catch (UnsupportedEncodingException e) {
            return e.toString();
        }
    }

    static String charset_convert(String input, String from, String to) throws UnsupportedEncodingException {
        byte[] inputBytes = input.getBytes();
        byte[] output = new String(inputBytes, from).getBytes(to);
        return helpers.bytesToString(output);
    }

    static String context_url(String properties, String key, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(key);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(hackvertor == null) {
            return properties;
        }

        HttpRequest req = hackvertor.getRequest();
        properties = properties.replace("$protocol", req.httpService().secure()? "https:" : "http");
        properties = properties.replace("$host", req.httpService().host());
        properties = properties.replace("$path", req.pathWithoutQuery());
        properties = properties.replace("$file", req.fileExtension());
        properties = properties.replace("$query", req.query());
        properties = properties.replace("$port", req.httpService().port()+"");
        return properties;
    }

    static String context_request(String key, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(key);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(hackvertor == null || hackvertor.getRequest() == null) {
            return "";
        }
        return hackvertor.getRequest().toString();
    }

    static String context_header(String properties, String key, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(key);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(hackvertor == null || hackvertor.getRequest() == null) {
            return properties;
        }
        HttpRequest analyzedRequest = hackvertor.getRequest();
        List<HttpHeader> headers = analyzedRequest.headers();
        for(HttpHeader header : headers) {
            properties = properties.replace("$" + header.name(), header.value());
        }
        return properties;
    }

    static String context_param(String properties, String key, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(key);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(hackvertor == null || hackvertor.getRequest() == null) {
            return properties;
        }
        HttpRequest analyzedRequest = hackvertor.getRequest();
        List<ParsedHttpParameter> params = analyzedRequest.parameters();
        for(ParsedHttpParameter param : params) {
            properties = properties.replace("$"+param.name(), param.value());
        }
        return properties;
    }

    static String context_body(String key, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(key);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(hackvertor == null || hackvertor.getRequest() == null) {
            return "";
        }
        return hackvertor.getRequest().bodyToString();
    }

    static String increment_var(HashMap<String, String> variableMap, int start, String variableName, Boolean enabled) {
        if(!enabled) {
          return "This tag is disabled until you enable it in the tag params to prevent unintentional variable declaration.";
        }
        int value = 0;
        if(variableMap.containsKey(variableName)) {
            value = Integer.parseInt(variableMap.get(variableName));
        } else {
            value = start;
        }
        String returnValue = String.valueOf(value);
        variableMap.put(variableName, String.valueOf(value+1));
        return returnValue;
    }

    static String decrement_var(HashMap<String, String> variableMap, int start, String variableName, Boolean enabled) {
        if(!enabled) {
          return "This tag is disabled until you enable it in the tag params to prevent unintentional variable declaration.";
        }
        int value = 0;
        if(variableMap.containsKey(variableName)) {
            value = Integer.parseInt(variableMap.get(variableName));
        } else {
            value = start;
        }
        String returnValue = String.valueOf(value);
        variableMap.put(variableName, String.valueOf(value-1));
        return returnValue;
    }

    static String json_parse(String input, String properties) {
        input = input.trim();
        return recursiveTraverse("", new JSONObject(input), properties);
    }

    private static String recursiveTraverse(String previousKey, JSONObject currentObject, String properties) {
        for (String currentKey : currentObject.keySet()) {
            String nextKey = previousKey == null || previousKey.isEmpty() ? currentKey : previousKey + "-" + currentKey;
            Object value = currentObject.get(currentKey);
            if (value instanceof JSONObject) {
                properties = recursiveTraverse(nextKey, (JSONObject) value, properties);
            } else if (value instanceof JSONArray) {
                JSONArray array = (JSONArray) value;
                for (int i = 0; i < array.length(); i++) {
                    Object object = array.get(i);
                    if (object instanceof JSONObject) {
                        JSONObject jsonObject = (JSONObject) object;
                        properties = recursiveTraverse(nextKey + "." + i, jsonObject, properties);
                    } else {
                        properties = properties.replace("$"+nextKey, object.toString());
                    }
                }
            } else {
                properties = properties.replace("$"+nextKey, value.toString());
            }
        }
        return properties;
    }

    static String utf7(String input, String excludePattern) {
        Pattern pattern = (excludePattern == null || excludePattern.isEmpty())
                ? null
                : Pattern.compile(excludePattern);

        StringBuilder output = new StringBuilder();
        StringBuilder toEncode = new StringBuilder();
        
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            
            // Check if character should be excluded from encoding (and is ASCII)
            if (pattern != null && pattern.matcher(String.valueOf(c)).matches() && c < 128) {
                // If we have accumulated characters to encode, encode them first
                if (toEncode.length() > 0) {
                    encodeUtf7Block(toEncode.toString(), output);
                    toEncode.setLength(0);
                }
                // Special handling for plus sign in UTF-7
                if (c == '+') {
                    output.append("+-");
                } else {
                    output.append(c);
                }
            } else {
                // Accumulate characters that need encoding
                toEncode.append(c);
            }
        }
        
        // Encode any remaining characters
        if (toEncode.length() > 0) {
            encodeUtf7Block(toEncode.toString(), output);
        }
        
        return output.toString();
    }
    
    private static void encodeUtf7Block(String text, StringBuilder output) {
        try {
            // Convert to UTF-16BE bytes for proper UTF-7 encoding
            byte[] utf16Bytes = text.getBytes("UTF-16BE");
            // Base64 encode and remove padding
            String base64 = helpers.base64Encode(utf16Bytes).replaceAll("=+$", "");
            // UTF-7 uses modified base64 (but we keep / as standard UTF-7)
            output.append('+').append(base64).append('-');
        } catch (Exception e) {
            // Fallback - should not happen
            for (char c : text.toCharArray()) {
                output.append('+')
                      .append(base64Encode("\u0000" + c).replaceAll("=+$", ""))
                      .append('-');
            }
        }
    }

    public static String utf7Decode(String input) {
        StringBuilder output = new StringBuilder();
        int i = 0;
        while (i < input.length()) {
            char c = input.charAt(i);
            if (c == '+') {
                if (i + 1 < input.length() && input.charAt(i + 1) == '-') {
                    output.append('+');
                    i += 2;
                } else {
                    int endIndex = input.indexOf('-', i + 1);
                    if (endIndex == -1) {
                        endIndex = input.length();
                    }
                    if (endIndex > i + 1) {
                        String base64Part = input.substring(i + 1, endIndex);
                        base64Part = base64Part.replace(',', '/');
                        int padding = (4 - base64Part.length() % 4) % 4;
                        for (int p = 0; p < padding; p++) {
                            base64Part += "=";
                        }
                        try {
                            byte[] bytes = helpers.base64Decode(base64Part);
                            for (int b = 0; b < bytes.length - 1; b += 2) {
                                int high = bytes[b] & 0xFF;
                                int low = bytes[b + 1] & 0xFF;
                                char decodedChar = (char) ((high << 8) | low);
                                output.append(decodedChar);
                            }
                        } catch (Exception e) {
                            output.append(input.substring(i, Math.min(endIndex + 1, input.length())));
                        }
                    }
                    i = endIndex;
                    if (i < input.length() && input.charAt(i) == '-') {
                        i++;
                    }
                }
            } else {
                output.append(c);
                i++;
            }
        }
        return output.toString();
    }

    static byte[] readUniBytes(String uniBytes) {
        byte[] result = new byte[uniBytes.length()];
        for (int i = 0; i < result.length; ++i) {
            result[i] = (byte) uniBytes.charAt(i);
        }
        return result;
    }

    static String brotli_decompress(String str) {
        byte[] buffer = new byte[65536];
        ByteArrayInputStream input = new ByteArrayInputStream(readUniBytes(str));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        BrotliInputStream brotliInput = null;
        try {
            brotliInput = new BrotliInputStream(input);
        } catch (IOException e) {
            return e.toString();
        }
        while (true) {
            int len = 0;
            try {
                len = brotliInput.read(buffer, 0, buffer.length);
            } catch (IOException e) {
                return e.toString();
            }
            if (len <= 0) {
                break;
            }
            output.write(buffer, 0, len);
        }
        try {
            brotliInput.close();
        } catch (IOException e) {
            return e.toString();
        }
        return output.toString();
    }

    static String gzip_compress(String input) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
        GZIPOutputStream gzip = null;
        try {
            gzip = new GZIPOutputStream(bos);
            gzip.write(input.getBytes());
            gzip.close();
            byte[] compressed = bos.toByteArray();
            bos.close();
            return helpers.bytesToString(compressed);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e.toString();
        }
    }

    static String gzip_decompress(String input) {
        ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
        GZIPInputStream gis = null;
        byte[] bytes;
        try {
            gis = new GZIPInputStream(bis);
            bytes = IOUtils.toByteArray(gis);
            return new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e.toString();
        }
    }

    static String bzip2_compress(String input) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
        CompressorOutputStream cos = null;
        try {
            cos = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.getBzip2(), bos);
        } catch (CompressorException e) {
            e.printStackTrace();
            return "Error creating compressor:" + e.toString();
        }
        try {
            cos.write(input.getBytes());
            cos.close();
            byte[] compressed = bos.toByteArray();
            bos.close();
            return helpers.bytesToString(compressed);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e.toString();
        }
    }

    static String bzip2_decompress(String input) {
        ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
        BZip2CompressorInputStream cis = null;
        byte[] bytes;
        try {
            cis = new BZip2CompressorInputStream(bis);
            bytes = IOUtils.toByteArray(cis);
            return new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e.toString();
        }
    }

    static String deflate_compress(String input, Boolean includeHeader) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
        CompressorOutputStream cos = null;
        DeflateParameters params = new DeflateParameters();
        params.setWithZlibHeader(includeHeader);
        cos = new DeflateCompressorOutputStream(bos, params);
        try {
            cos.write(input.getBytes());
            cos.close();
            byte[] compressed = bos.toByteArray();
            bos.close();
            return helpers.bytesToString(compressed);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e;
        }
    }

    static String deflate_decompress(String input, Boolean includeHeader) {
        ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
        DeflateCompressorInputStream cis = null;
        byte[] bytes;
        try {
            DeflateParameters params = new DeflateParameters();
            params.setWithZlibHeader(includeHeader);
            cis = new DeflateCompressorInputStream(bis, params);
            bytes = IOUtils.toByteArray(cis);
            cis.close();
            bis.close();
            return new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e;
        }
    }

    static String timestamp() {
        long unixTime = System.currentTimeMillis() / 1000L;
        return unixTime + "";
    }

    static String date(String format, String timezone) {
        try {
            SimpleDateFormat dateF = new SimpleDateFormat(format);
            dateF.setTimeZone(TimeZone.getTimeZone(timezone));
            Date now = new Date();
            return dateF.format(now);
        } catch (IllegalArgumentException e) {
            return "Invalid date format";
        }
    }

    static String html_entities(String str) {
        return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
    }

    static String decode_html_entities(String str) {
        return HtmlEscape.unescapeHtml(str);
    }

    static String base32_encode(String str) {
        Base32 base32 = new Base32();
        return helpers.bytesToString(base32.encode(helpers.stringToBytes(str)));
    }

    static String decode_base32(String str) {
        Base32 base32 = new Base32();
        return helpers.bytesToString(base32.decode(str.getBytes()));
    }

    static String base58_encode(String str) {
        return Base58.encode(helpers.stringToBytes(str));
    }

    static String decode_base58(String str) {
        return helpers.bytesToString(Base58.decode(str));
    }

    static String base64Encode(String str) {
        return helpers.base64Encode(str);
    }

    static String decode_base64(String str) {
        try {
            str = helpers.bytesToString(helpers.base64Decode(str));
        } catch (Exception e) {
            stderr.println(e.getMessage());
        }
        return str;
    }

    static String base64urlEncode(String str) {
        return base64Encode(str).replaceAll("\\+", "-").replaceAll("/", "_").replaceAll("=+$", "");
    }

    static String saml(String input) {
        return urlencode(base64Encode(deflate_compress(input, false)));
    }
    static String d_saml(String input) {
        String decodedUrl = decode_url(input);
        if(isBase64(decodedUrl, true)) {
            return deflate_decompress(decode_base64(decodedUrl), false);
        } else {
            return deflate_decompress(decode_base64(input), false);
        }
    }

    static String decode_base64url(String str) {
        str = str.replaceAll("-", "+");
        str = str.replaceAll("_", "/");
        switch (str.length() % 4) {
            case 0:
                break;
            case 2:
                str += "==";
                break;
            case 3:
                str += "=";
                break;
        }
        return helpers.bytesToString(helpers.base64Decode(str));
    }

    static String burp_urlencode(String str) {
        str = helpers.urlEncode(str);
        return str;
    }

    static String urlencode(String str) {
        try {
            str = URLEncoder.encode(str, "UTF-8");
        } catch (Exception e) {
            stderr.println(e.getMessage());
        }
        return str;
    }

    static String urlencode_not_plus(String str) {
        try {
            str = URLEncoder.encode(str, "UTF-8").replaceAll("\\+", "%20");
        } catch (Exception e) {
            stderr.println(e.getMessage());
        }
        return str;
    }

    static String urlencode_all(String str) {
        StringBuilder converted = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            int codePoint = Character.codePointAt(str, i);
            if (codePoint <= 0x7f) {
                converted.append("%" + String.format("%02X", codePoint));
            } else {
                try {
                    converted.append(URLEncoder.encode(Character.toString(str.charAt(i)), "UTF-8"));
                } catch (Exception e) {
                    stderr.println(e.getMessage());
                }
            }
        }
        return converted.toString();
    }

    static String burp_decode_url(String str) {
        str = helpers.urlDecode(str);
        return str;
    }

    static String decode_url(String str) {
        try {
            str = URLDecoder.decode(str, "UTF-8");
        } catch (Exception e) {
            stderr.println(e.getMessage());
        }
        return str;
    }

    static String random_num(int len) {
        return random("0123456789", len, false);
    }

    static String random_alpha_lower(int len) {
        return random("abcdefghijklmnopqrstuvwxyz", len, false);
    }

    static String random_alphanum_lower(int len) {
        return random("0123456789abcdefghijklmnopqrstuvwxyz", len, false);
    }

    static String random_alpha_upper(int len) {
        return random("ABCDEFGHIJKLMNOPQRSTUVWXYZ", len, false);
    }

    static String random_alphanum_upper(int len) {
        return random("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", len, false);
    }

    static String random_alpha_mixed(int len) {
        return random("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", len, false);
    }

    static String random_alphanum_mixed(int len) {
        return random("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", len, false);
    }

    static String random_hex(int len) {
        return random("0123456789abcdef", len, false);
    }

    static String random_hex_mixed(int len) {
        return random("0123456789abcdefABCDEF", len, false);
    }

    static String random(String chars, int len, Boolean everyCharacterOnce) {
        Set<Character> usedChars = chars.chars().mapToObj(e->(char)e).collect(Collectors.toSet());
        if (len > 0 && chars.length() > 0) {
            StringBuilder sb = new StringBuilder();
            Random random = new Random();
            int i = 0;
            while(i < len) {
                if(everyCharacterOnce && usedChars.size() > 0) {
                    char chr = usedChars.stream().skip(new Random().nextInt(usedChars.size())).findFirst().orElse(null);
                    sb.append(chr);
                    usedChars.remove(chr);
                } else {
                    int randomNum = random.nextInt(chars.length());
                    char chr = chars.charAt(randomNum);
                    sb.append(chr);
                }
                i++;
            }
            return sb.toString();
        }
        return "";
    }

    static String random_unicode(int from, int to, int amount) {
        String out = "";
        try {
            for (int i = 0; i < amount; i++) {
                Random random = new Random();
                int n = random.nextInt(to) + from;
                out += (char) n;
            }
            return out;
        } catch (Exception e) {
            return "Unable to create unicode characters";
        }
    }

    static String uppercase(String str) {
        return StringUtils.upperCase(str);
    }

    static String lowercase(String str) {
        return StringUtils.lowerCase(str);
    }

    static String lowercaseFirst(String str) {
        return Character.toLowerCase(str.charAt(0)) + str.substring(1);
    }

    static String unique(String str) {
        String words[] = str.split(" ");
        Set result = new HashSet(Arrays.asList(words));
        return String.join(" ", result);
    }

    static String remove_output(String input) {
        return "";
    }
    static String capitalise(String str) {
        return StringUtils.capitalize(str);
    }

    static String uncapitalise(String str) {
        return StringUtils.uncapitalize(str);
    }

    static String html5_entities(String str) {
        return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
    }

    static String decode_html5_entities(String str) {
        return HtmlEscape.unescapeHtml(str);
    }

    static String hex(String str, String separator) {
        return ascii2hex(str, separator);
    }

    static String hex_entities(String str) {
        return HtmlEscape.escapeHtml(str, HtmlEscapeType.HEXADECIMAL_REFERENCES, HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String dec_entities(String str) {
        return HtmlEscape.escapeHtml(str, HtmlEscapeType.DECIMAL_REFERENCES, HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String jwt(String payload, String algo, String secret) {
        try {
            algo = algo.toUpperCase();
            String algoName;
            if (algo.equals("HS256")) {
                algoName = "HmacSHA256";
            } else if (algo.equals("HS384")) {
                algoName = "HmacSHA384";
            } else if (algo.equals("HS512")) {
                algoName = "HmacSHA512";
            } else if (algo.equals("NONE")) {
                algoName = "none";
            } else {
                return "Unsupported algorithm";
            }
            String message = "";
            // Build header JSON manually to ensure consistent field order (alg before typ)
            String headerJsonStr = "{\"alg\":\"" + algo + "\",\"typ\":\"JWT\"}";
            JSONObject payloadJson = new JSONObject(payload);
            message = base64urlEncode(headerJsonStr) + "." + base64urlEncode(payloadJson.toString());
            if (!algoName.equals("none")) {
                // Handle empty secret case - HMAC requires at least 1 byte
                byte[] secretBytes = secret.getBytes();
                if (secretBytes.length == 0) {
                    // For empty secret, use a single null byte which is the standard behavior
                    secretBytes = new byte[]{0};
                }
                
                Mac hashMac = Mac.getInstance(algoName);
                SecretKeySpec secret_key = new SecretKeySpec(secretBytes, algoName);
                hashMac.init(secret_key);
                // Encode the raw HMAC bytes directly to base64url, don't convert to string first
                byte[] signature = hashMac.doFinal(message.getBytes());
                String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
                return message + "." + encodedSignature;
            } else {
                return message + ".";
            }
        } catch (Exception e) {
            return "Unable to create token";
        }
    }

    static String d_jwt_get_payload(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return decode_base64url(jwt.getPayload());
        } catch (JWTDecodeException exception) {
            return "Invalid token";
        }
    }

    static String d_jwt_get_header(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return decode_base64url(jwt.getHeader());
        } catch (JWTDecodeException exception) {
            return "Invalid token";
        }
    }

    static String d_jwt_verify(String token, String secret) {
        DecodedJWT jwt;
        try {
            jwt = JWT.decode(token);
        } catch (JWTDecodeException exception) {
            return "Invalid token";
        }
        try {
            String algo = jwt.getAlgorithm().toUpperCase();
            Algorithm algorithm = null;
            if (algo.equals("HS256")) {
                algorithm = Algorithm.HMAC256(secret);
            } else if (algo.equals("HS384")) {
                algorithm = Algorithm.HMAC384(secret);
            } else if (algo.equals("HS512")) {
                algorithm = Algorithm.HMAC512(secret);
            } else {
                return "0";
            }
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            verifier.verify(token);
            return "1";
        } catch (IllegalArgumentException e) {
            return "0";
        } catch (Exception exception) {
            return "0";
        }
    }

    static String hex_escapes(String str) {
        return JavaScriptEscape.escapeJavaScript(str, JavaScriptEscapeType.XHEXA_DEFAULT_TO_UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String octal_escapes(String str) {
        StringBuilder converted = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            converted.append("\\" + Integer.toOctalString(Character.codePointAt(str, i)));
        }
        return converted.toString();
    }

    static String decode_octal_escapes(String str) {
        return decode_js_string(str);
    }

    static String css_escapes(String str) {
        return CssEscape.escapeCssString(str, CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String css_escapes6(String str) {
        return CssEscape.escapeCssString(str, CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String unicode_escapes(String str) {
        return JavaScriptEscape.escapeJavaScript(str, JavaScriptEscapeType.UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
    }

    static String quoted_printable(String str) {
        QuotedPrintableCodec codec = new QuotedPrintableCodec();
        try {
            return codec.encode(str);
        } catch (EncoderException e) {
            return "Error encoding:"+e.toString();
        }
    }

    static String powershell(String cmd) {
        return base64Encode(convertCharset(cmd, "UTF-16LE"));
    }

    static String js_string(String str) {
        return JsonEscape.escapeJson(str);
    }

    static String unicode_alternatives(String input) {
        StringBuilder output = new StringBuilder();
        HashMap<Character,StringBuilder> cache = new HashMap<>();
        int len = input.length();
        for (int i = 0; i < len; i++) {
            char originalChr = input.charAt(i);
            if(input.codePointAt(i) > 0x7f) {
                output.append(originalChr);
                continue;
            }
            boolean foundVariant = false;
            StringBuilder unicodeCharacters = new StringBuilder();
            if(cache.containsKey(originalChr)) {
                output.append(cache.get(originalChr));
                continue;
            }
            for(int j=0x7f;j<0xffff;j++) {
                String chr = new StringBuilder().appendCodePoint(j).toString();
                String normalized = Normalizer.normalize(chr, Normalizer.Form.NFKC);
                if(normalized.equals(String.valueOf(originalChr))) {
                    unicodeCharacters.append(chr);
                    foundVariant = true;
                }
            }
            if(!foundVariant) {
                output.append(originalChr);
            } else {
                output.append(unicodeCharacters);
                cache.put(originalChr, unicodeCharacters);
            }
        }
        return output.toString();
    }

    static String d_quoted_printable(String str) {
        str = str.replace("=\n","");
        QuotedPrintableCodec codec = new QuotedPrintableCodec();
        try {
            return codec.decode(str);
        } catch (DecoderException e) {
            return "Error decoding:"+e.toString();
        }
    }
    static String php_non_alpha(String input) {
        String converted = "";
        converted += "$_[]++;$_[]=$_._;";
        converted += "$_____=$_[(++$__[])][(++$__[])+(++$__[])+(++$__[])];";
        converted += "$_=$_[$_[+_]];";
        converted += "$___=$__=$_[++$__[]];";
        converted += "$____=$_=$_[+_];";
        converted += "$_++;$_++;$_++;";
        converted += "$_=$____.++$___.$___.++$_.$__.++$___;";
        converted += "$__=$_;";
        converted += "$_=$_____;";
        converted += "$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;";
        converted += "$___=+_;";
        converted += "$___.=$__;";
        converted += "$___=++$_^$___[+_];$\u00c0=+_;$\u00c1=$\u00c2=$\u00c3=$\u00c4=$\u00c6=$\u00c8=$\u00c9=$\u00ca=$\u00cb=++$\u00c1[];";
        converted += "$\u00c2++;";
        converted += "$\u00c3++;$\u00c3++;";
        converted += "$\u00c4++;$\u00c4++;$\u00c4++;";
        converted += "$\u00c6++;$\u00c6++;$\u00c6++;$\u00c6++;";
        converted += "$\u00c8++;$\u00c8++;$\u00c8++;$\u00c8++;$\u00c8++;";
        converted += "$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;";
        converted += "$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;";
        converted += "$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;";
        converted += "$__('$_=\"'";
        String[] lookup = {"\u00c0", "\u00c1", "\u00c2", "\u00c3", "\u00c4", "\u00c6", "\u00c8", "\u00c9", "\u00ca", "\u00cb"};
        for (int i = 0; i < input.length(); i++) {
            ArrayList<String> vars = new ArrayList<String>();
            String chrs = Integer.toOctalString(Character.codePointAt(input, i)).toString();
            for (int j = 0; j < chrs.length(); j++) {
                vars.add("$" + lookup[Integer.parseInt(chrs.charAt(j) + "")]);
            }
            converted += ".$___." + StringUtils.join(vars, ".");
        }
        converted += ".'";
        converted += "\"');$__($_);";
        return "<?php " + converted + "?>";
    }

    static String php_chr(String str) {
        ArrayList<String> output = new ArrayList<String>();
        for (int i = 0; i < str.length(); i++) {
            output.add("chr(" + Character.codePointAt(str, i) + ")");
        }
        return StringUtils.join(output, ".");
    }

    static String sql_hex(String str) {
        return "0x" + ascii2hex(str, "");
    }

    static String rotN(String str, int n) {
        String out = "";
        int len = str.length();
        for (int i = 0; i < len; i++) {
            char chr = str.charAt(i);
            int chrCode = (int) chr;
            if (Character.isLowerCase(chr)) {
                out += (char) ((chrCode - 97 + n) % 26 + 97);
            } else if (Character.isUpperCase(str.charAt(i))) {
                out += (char) ((chrCode - 65 + n) % 26 + 65);
            } else {
                out += chr;
            }
        }
        return out;
    }

    static String aes_encrypt(String plaintext, String key, String transformations, String iv) {
        try {
            return AES.encrypt(plaintext, key, transformations, iv);
        } catch (NoSuchAlgorithmException e) {
            return "No such algorithm exception:" + e.toString();
        } catch (UnsupportedEncodingException e) {
            return "Unsupported encoding exception:" + e.toString();
        } catch (IllegalArgumentException e) {
            return "Invalid key length" + e.toString();
        } catch (Exception e) {
            return "Error exception:" + e.toString();
        }
    }

    static String aes_decrypt(String ciphertext, String key, String transformations, String iv) {
        try {
            return AES.decrypt(ciphertext, key, transformations, iv);
        } catch (NoSuchAlgorithmException e) {
            return "No such algorithm exception:" + e.toString();
        } catch (UnsupportedEncodingException e) {
            return "Unsupported encoding exception:" + e.toString();
        } catch (IllegalArgumentException e) {
            return "Invalid key length" + e.toString();
        } catch (Exception e) {
            return "Error exception:" + e.toString();
        }
    }

    static String xor(String message, String key) {
        try {
            int len = message.length();
            int keyLen = key.length();
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < len; i++) {
                output.append((char) (message.charAt(i) ^ key.charAt(i % keyLen)));
            }
            return output.toString();
        } catch (Exception e) {
            return "Unable to encode";
        }
    }

    static int guess_key_length(String ciphertext) {
        int max = 30;
        TreeMap<Integer, Double> totalIC = new TreeMap<Integer, Double>();
        TreeMap<Integer, Double> normalizedIC = new TreeMap<Integer, Double>();
        for (int candidateLength = 2; candidateLength <= max; candidateLength++) {
            double[][] frequencies = new double[256][max + 1];
            for (int pos = 0; pos < ciphertext.length(); pos++) {
                int column = pos % candidateLength;
                int cp = ciphertext.codePointAt(pos);
                if (cp <= 255 && cp > -1) {
                    frequencies[ciphertext.codePointAt(pos)][column] += 1;
                }
            }

            double[] lengthN = new double[max + 1];
            for (int column = 0; column < candidateLength; column++) {
                for (int character = 0; character <= 255; character++) {
                    lengthN[column] += frequencies[character][column];
                }
            }
            for (int column = 0; column < candidateLength; column++) {
                for (int character = 0; character <= 255; character++) {
                    frequencies[character][column] *= frequencies[character][column] * (frequencies[character][column] - 1);
                }
            }
            double[] frequencySum = new double[max + 1];
            for (int column = 0; column < candidateLength; column++) {
                for (int character = 0; character <= 255; character++) {
                    frequencySum[column] += frequencies[character][column];
                }
            }
            double[] columnIC = new double[max + 1];
            for (int column = 0; column < candidateLength; column++) {
                if (lengthN[column] > 1) {
                    columnIC[column] = frequencySum[column] / (lengthN[column] * (lengthN[column] - 1.0));
                }
            }
            double ic = 0;
            for (int column = 0; column < candidateLength; column++) {
                ic += columnIC[column];
            }
            totalIC.put(candidateLength, ic);
        }
        Map sortedMap = sortByValuesDesc(totalIC);
        Iterator it = sortedMap.entrySet().iterator();
        int pos = 0;
        while (it.hasNext()) {
            if (pos > 8) {
                break;
            }
            Map.Entry pair = (Map.Entry) it.next();
            int key = (int) pair.getKey();
            normalizedIC.put(key, (double) pair.getValue() / key);
            pos++;
        }
        sortedMap = sortByValuesDesc(normalizedIC);
        it = sortedMap.entrySet().iterator();
        Map.Entry pair = (Map.Entry) it.next();
        return (int) pair.getKey();
    }

    static int getScore(char clearTextByte) {
        int score = 0;
        if (clearTextByte >= ' ' && clearTextByte < '\u00ff') {
            score += 1;
        }
        if ((clearTextByte >= 'A') && (clearTextByte <= 'Z')) {
            score += 1;
        }
        if ((clearTextByte >= 'a') && (clearTextByte <= 'z')) {
            score += 2;
        }
        if (clearTextByte == ' ') {
            score += 5;
        }
        if (clearTextByte == ',') {
            score += 2;
        }
        if ((clearTextByte == '.') || (clearTextByte == '!') ||
                (clearTextByte == ';') || (clearTextByte == '?')) {
            score += 1;
        }
        return score;
    }

    static String xor_decrypt(String ciphertext, int keyLength, boolean returnKey) {
        if (keyLength < 1) {
            return "Unable to decrypt";
        }
        String[] guessedKey = new String[keyLength];
        ArrayList<ArrayList<Character>> potentialKeys = new ArrayList<>();
        ArrayList<ArrayList<Character>> blacklistChars = new ArrayList<>();
        ArrayList<ArrayList<Character>> filteredKeys = new ArrayList<>();
        for (int i = 0; i < keyLength; i++) {
            potentialKeys.add(new ArrayList<>());
            blacklistChars.add(new ArrayList<>());
            filteredKeys.add(new ArrayList<>());
        }
        for (int column = 0; column < keyLength; column++) {
            double maxScore = 0;
            for (int keyByte = 0; keyByte <= 255; keyByte++) {
                int score = 0;
                for (int pos = 0; pos < ciphertext.length(); pos++) {
                    if ((pos - column) % keyLength == 0) {
                        char clearTextByte = (char) (ciphertext.charAt(pos) ^ (char) keyByte);
                        score += getScore(clearTextByte);
                        if ((clearTextByte >= 'A' && clearTextByte <= 'Z') || (clearTextByte >= 'a' && clearTextByte <= 'z') || clearTextByte == ' ') {
                            if (!potentialKeys.get(column).contains((char) keyByte)) {
                                potentialKeys.get(column).add((char) keyByte);
                            }
                        }
                    }
                }
                if (score > maxScore) {
                    maxScore = score;
                    guessedKey[column] = "" + (char) keyByte;
                }
            }
        }
        if (keyLength <= 10 && ciphertext.length() < 200 && (((float) keyLength / ciphertext.length()) * 100) <= 20) {
            for (int pos = 0; pos < ciphertext.length(); pos++) {
                int keypos = pos % keyLength;
                char chr = ciphertext.charAt(pos);
                ArrayList<Character> potentialKeyChars = potentialKeys.get(keypos);
                for (int j = 0; j < potentialKeyChars.size(); j++) {
                    char potentialChr = potentialKeyChars.get(j);
                    char clearTextByte = (char) (chr ^ potentialChr);
                    if ((clearTextByte >= 'A' && clearTextByte <= 'Z') || (clearTextByte >= 'a' && clearTextByte <= 'z') || clearTextByte == ' ') {

                    } else {
                        blacklistChars.get(keypos).add(potentialChr);
                    }
                }
            }
            for (int i = 0; i < keyLength; i++) {
                ArrayList<Character> pKeys = potentialKeys.get(i);
                ArrayList<Character> blacklist = blacklistChars.get(i);
                for (int j = 0; j < pKeys.size(); j++) {
                    if (!blacklist.contains(pKeys.get(j)) && filteredKeys.get(i).size() < 10) {
                        filteredKeys.get(i).add(pKeys.get(j));
                    }
                }
            }
            ArrayList<String> keyPermutations = new ArrayList<>();
            doOneChar("", 0, filteredKeys, keyPermutations, guessedKey);
            double maxScore = -999999999;
            String bestKey = "";
            for (String key : keyPermutations) {
                double score = is_like_english(xor(ciphertext, key));
                if (score >= maxScore) {
                    bestKey = key;
                    maxScore = score;
                }
            }
            guessedKey = bestKey.split("");
        }
        if (returnKey) {
            return StringUtils.join(guessedKey, "");
        } else {
            return xor(ciphertext, StringUtils.join(guessedKey, ""));
        }
    }

    static void doOneChar(String key, int l, ArrayList<ArrayList<Character>> charCandidates, ArrayList<String> keyPermutations, String[] guessedKey) {
        if (l == charCandidates.size()) {
            keyPermutations.add(key);
            return;
        }
        if (charCandidates.get(l).size() == 0) {
            doOneChar(key + guessedKey[l], l + 1, charCandidates, keyPermutations, guessedKey);
        } else {
            for (char c : charCandidates.get(l)) {
                doOneChar(key + c, l + 1, charCandidates, keyPermutations, guessedKey);
            }
        }
    }

    static String xor_getkey(String ciphertext) {
        int len = guess_key_length(ciphertext);
        return xor_decrypt(ciphertext, len, true);
    }

    static String affine_encrypt(String message, int key1, int key2) {
        int[] keyArray1 = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
        int[] keyArray2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
        String encoded = "";
        if (!IntStream.of(keyArray1).anyMatch(x -> x == key1)) {
            return "Invalid key1 must be one of:1,3,5,7,9,11,15,17,19,21,23,25";
        }
        if (!IntStream.of(keyArray2).anyMatch(x -> x == key2)) {
            return "Invalid key2 must be one of:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25";
        }
        message = message.toLowerCase();
        for (int i = 0; i < message.length(); i++) {
            char chr = message.charAt(i);
            if (Character.isLowerCase(chr)) {
                int chrCode = Character.codePointAt(message, i) - 97;
                int newChrCode = ((key1 * chrCode + key2) % 26) + 97;
                encoded += (char) newChrCode;
            } else {
                encoded += chr;
            }
        }
        return encoded;
    }

    static String affine_decrypt(String ciphertext, int key1, int key2) {
        int[] keyArray1 = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
        int[] keyArray2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
        String plaintext = "";
        if (!IntStream.of(keyArray1).anyMatch(x -> x == key1)) {
            return "Invalid key1 must be one of:1,3,5,7,9,11,15,17,19,21,23,25";
        }
        if (!IntStream.of(keyArray2).anyMatch(x -> x == key2)) {
            return "Invalid key2 must be one of:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25";
        }
        int multinverse = 1;
        for (int i = 1; i <= 25; i = i + 2) {
            if ((key1 * i) % 26 == 1) {
                multinverse = i;
            }
        }
        for (int i = 0; i < ciphertext.length(); i++) {
            char chr = ciphertext.charAt(i);
            if (Character.isLowerCase(chr)) {
                int chrCode = Character.codePointAt(ciphertext, i) - 97;
                int newChrCode = ((multinverse * (chrCode + 26 - key2)) % 26) + 97;
                plaintext += (char) newChrCode;
            } else {
                plaintext += chr;
            }
        }
        return plaintext;
    }

    static String atbash_encrypt(String message) {
        StringBuilder encoded = new StringBuilder();
        String keyUpper = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
        String keyLower = keyUpper.toLowerCase();
        for (int i = 0; i < message.length(); i++) {
            char chr = message.charAt(i);
            if (Character.isUpperCase(chr)) {
                encoded.append(keyUpper.charAt(message.codePointAt(i) - 65));
            } else if (Character.isLowerCase(chr)) {
                encoded.append(keyLower.charAt(message.codePointAt(i) - 97));
            } else {
                encoded.append(chr);
            }
        }
        return encoded.toString();
    }

    static String atbash_decrypt(String ciphertext) {
        StringBuilder plaintext = new StringBuilder();
        String keyUpper = "ZYXWVUTSRQPONMLKJIHGFEDCBA";
        String keyLower = keyUpper.toLowerCase();
        for (int i = 0; i < ciphertext.length(); i++) {
            char chr = ciphertext.charAt(i);
            if (Character.isUpperCase(chr)) {
                plaintext.append((char) (keyUpper.indexOf(ciphertext.charAt(i)) + 65));
            } else if (Character.isLowerCase(chr)) {
                plaintext.append((char) (keyLower.indexOf(ciphertext.charAt(i)) + 97));
            } else {
                plaintext.append(chr);
            }
        }
        return plaintext.toString();
    }

    static String rotN_bruteforce(String str) {
        String out = "";
        for (int i = 1; i <= 25; i++) {
            out += i + "=" + rotN(str, i) + "\n";
        }
        return out;
    }

    static String rail_fence_encrypt(String message, int key) {
        String ciphertext = "";
        message = message.toLowerCase().replaceAll("[^a-z]", "");
        if (key < 1) {
            return "";
        }
        if (message.length() < 1) {
            return "";
        }
        if (key > Math.floor(2 * message.length() - 1)) {
            return "Error: key is too large for plaintext length";
        }
        if (key == 1) {
            return message;
        } else {
            int line = 0;
            for (line = 0; line < key - 1; line++) {
                int skip = 2 * (key - line - 1);
                int j = 0;
                for (int i = line; i < message.length(); ) {
                    ciphertext += message.charAt(i);
                    if ((line == 0) || (j % 2 == 0)) {
                        i += skip;
                    } else {
                        i += 2 * (key - 1) - skip;
                    }
                    j++;
                }
            }
            for (int i = line; i < message.length(); i += 2 * (key - 1)) {
                ciphertext += message.charAt(i);
            }
            return ciphertext;
        }

    }

    static String rail_fence_decrypt(String encoded, int key) {
        String plaintext = "";
        encoded = encoded.toLowerCase().replaceAll("[^a-z]", "");
        if (key < 1) {
            return "";
        }
        if (encoded.length() < 1) {
            return "";
        }
        if (key > Math.floor(2 * encoded.length() - 1)) {
            return "Error: key is too large for plaintext length";
        }
        if (key == 1) {
            return encoded;
        } else {
            String[] pt = new String[encoded.length()];
            int k = 0;
            int line = 0;
            for (line = 0; line < key - 1; line++) {
                int skip = 2 * (key - line - 1);
                int j = 0;
                for (int i = line; i < encoded.length(); ) {
                    pt[i] = "" + encoded.charAt(k++);
                    if ((line == 0) || (j % 2 == 0)) {
                        i += skip;
                    } else {
                        i += 2 * (key - 1) - skip;
                    }
                    j++;
                }
            }
            for (int i = line; i < encoded.length(); i += 2 * (key - 1)) {
                pt[i] = "" + encoded.charAt(k++);
            }
            plaintext = String.join("", pt);
        }
        return plaintext;
    }

    static String substitution_encrypt(String message, String key) {
        String ciphertext = "";
        message = message.toLowerCase();
        key = key.replaceAll("[^a-z]", "");
        if (key.length() != 26) {
            return "Error: Key length must be 26 characters";
        }
        if (message.length() < 1) {
            return "";
        }
        for (int i = 0; i < message.length(); i++) {
            char chr = message.charAt(i);
            if (Character.isLowerCase(chr)) {
                ciphertext += key.charAt(message.codePointAt(i) - 97);
            } else {
                ciphertext += "" + chr;
            }
        }
        return ciphertext;
    }

    static String substitution_decrypt(String ciphertext, String key) {
        ciphertext = ciphertext.toLowerCase();
        String plaintext = "";
        key = key.toLowerCase().replaceAll("[^a-z]", "");
        if (key.length() != 26) {
            return "Error: Key length must be 26 characters";
        }
        if (ciphertext.length() < 1) {
            return "";
        }
        for (int i = 0; i < ciphertext.length(); i++) {
            char chr = ciphertext.charAt(i);
            if (Character.isLowerCase(chr)) {
                plaintext += (char) (key.indexOf(ciphertext.charAt(i)) + 97);
            } else {
                plaintext += ciphertext.charAt(i);
            }
        }
        return plaintext;
    }

    static String decode_js_string(String str) {
        return JavaScriptEscape.unescapeJavaScript(str);
    }

    static String decode_css_escapes(String str) {
        return CssEscape.unescapeCss(str);
    }

    static String dec2hex(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                String hex = Integer.toHexString(Integer.parseInt(regexMatcher.group()));
                if(hex.length() == 1) {
                    hex = "0" + hex;
                }
                regexMatcher.appendReplacement(result, hex);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String if_regex(String str, String regex, String value) {
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(value);
        if(regexMatcher.find()) {
            return str;
        }
        return "";
    }
    static String if_not_regex(String str, String regex, String value) {
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(value);
        if(!regexMatcher.find()) {
            return str;
        }
        return "";
    }
    static String chunked_dec2hex(String str) {
        try {
            return Integer.toHexString(Integer.parseInt(str));
        } catch (NumberFormatException e) {
            return e.getMessage();
        }
    }

    static String dec2oct(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                String oct = Integer.toOctalString(Integer.parseInt(regexMatcher.group()));
                regexMatcher.appendReplacement(result, oct);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String dec2bin(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                String bin = Integer.toBinaryString(Integer.parseInt(regexMatcher.group()));
                regexMatcher.appendReplacement(result, bin);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String hex2dec(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                regexMatcher.appendReplacement(result, Integer.toString(Integer.parseInt(regexMatcher.group().replaceFirst("^0[xX]",""), 16)));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String oct2dec(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                regexMatcher.appendReplacement(result, Integer.toString(Integer.parseInt(regexMatcher.group(), 8)));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String bin2dec(String str, String regex) {
        StringBuffer result = new StringBuffer();
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher regexMatcher = pattern.matcher(str);
        while (regexMatcher.find()) {
            try {
                regexMatcher.appendReplacement(result, Integer.toString(Integer.parseInt(regexMatcher.group(), 2)));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return regexMatcher.appendTail(result).toString();
    }

    static String from_charcode(String str) {
        String[] chars = str.split("[\\s,]");
        String output = "";
        for (int i = 0; i < chars.length; i++) {
            try {
                output += Character.toString((char) Integer.parseInt(chars[i]));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return output;
    }

    static String to_charcode(String str) {
        ArrayList<Integer> output = new ArrayList<Integer>();
        for (int i = 0; i < str.length(); i++) {
            output.add(Character.codePointAt(str, i));
        }
        return StringUtils.join(output, ",");
    }

    static String ascii2bin(String str) {
        String output = "";
        for (int i = 0; i < str.length(); i++) {
            try {
                output += Integer.toBinaryString(Character.codePointAt(str, i));
                output += " ";
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return output;
    }

    static String bin2ascii(String str) {
        String[] chars = str.split(" ");
        String output = "";
        for (int i = 0; i < chars.length; i++) {
            try {
                output += Character.toString((char) Integer.parseInt(chars[i], 2));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return output;
    }

    public static String ascii2hex(String str, String separator) {
        StringBuilder output = new StringBuilder();
        String hex = "";
        for (int i = 0; i < str.length(); i++) {
            try {
                hex = Integer.toHexString(Character.codePointAt(str, i));
                if (hex.length() % 2 != 0) {
                    hex = "0" + hex;
                }
                output.append(hex);
                if (!separator.isEmpty() && i < str.length() - 1) {
                    output.append(separator);
                }
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return output.toString();
    }

    static String ascii2reverse_hex(String str, String separator) {
        String hex = "";
        java.util.List<String> output = new ArrayList<>();
        for (int i = 0; i < str.length(); i++) {
            try {
                hex = Integer.toHexString(Character.codePointAt(str, i));
                if (hex.length() % 2 != 0) {
                    hex = "0" + hex;
                }
                output.add(hex);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        Collections.reverse(output);
        return StringUtils.join(output, "");
    }

    static String hex2ascii(String str) {
        Pattern p = Pattern.compile("([0-9a-fA-F]{2})(?:[\\s,\\-]?)");
        Matcher m = p.matcher(str);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            m.appendReplacement(sb, "");
            sb.append(Character.toString((char) Integer.parseInt(m.group(1), 16)));
        }
        return sb.toString();
    }

    static String hmac(String str, String key, String algoName) {
        Mac hashMac = null;
        try {
            hashMac = Mac.getInstance(algoName);
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), algoName);
            hashMac.init(secret_key);

            return org.bouncycastle.util.encoders.Hex.toHexString(hashMac.doFinal(str.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();

            return e.getMessage();
        }
    }

    static String hmacmd5(String str, String key) {
        return hmac(str, key, "HmacMD5");
    }

    static String hmacsha1(String str, String key) {
        return hmac(str, key, "HmacSHA1");
    }

    static String hmacsha224(String str, String key) {
        return hmac(str, key, "HmacSHA224");
    }

    static String hmacsha256(String str, String key) {
        return hmac(str, key, "HmacSHA256");
    }

    static String hmacsha384(String str, String key) {
        return hmac(str, key, "HmacSHA384");
    }

    static String hmacsha512(String str, String key) {
        return hmac(str, key, "HmacSHA512");
    }

    static String fake(String name, String properties, String locale) {
        Faker faker = new Faker(new Locale(locale));
        name = name.replaceFirst("^fake_", "");
        name = name.replaceAll("[^\\w]+","");

        // Get the faker component and replace properties
        Object fakerComponent = getFakerComponent(faker, name);
        if (fakerComponent != null) {
            return replaceFakerProperties(fakerComponent, name, properties);
        }
        return "";
    }

    private static Object getFakerComponent(Faker faker, String name) {
        switch(name) {
            case "address": return faker.address();
            case "ancient": return faker.ancient();
            case "animal": return faker.animal();
            case "app": return faker.app();
            case "artist": return faker.artist();
            case "avatar": return faker.avatar();
            case "aviation": return faker.aviation();
            case "book": return faker.book();
            case "bool": return faker.bool();
            case "business": return faker.business();
            case "code": return faker.code();
            case "currency": return faker.currency();
            case "color": return faker.color();
            case "commerce": return faker.commerce();
            case "company": return faker.company();
            case "crypto": return faker.crypto();
            case "date": return faker.date();
            case "demographic": return faker.demographic();
            case "educator": return faker.educator();
            case "file": return faker.file();
            case "finance": return faker.finance();
            case "food": return faker.food();
            case "hacker": return faker.hacker();
            case "idNumber": return faker.idNumber();
            case "internet": return faker.internet();
            case "job": return faker.job();
            case "lorem": return faker.lorem();
            case "music": return faker.music();
            case "name": return faker.name();
            case "nation": return faker.nation();
            case "number": return faker.number();
            case "options": return faker.options();
            case "phoneNumber": return faker.phoneNumber();
            case "slackEmoji": return faker.slackEmoji();
            case "space": return faker.space();
            case "stock": return faker.stock();
            case "team": return faker.team();
            case "university": return faker.university();
            case "weather": return faker.weather();
            default: return null;
        }
    }

    private static String replaceFakerProperties(Object component, String componentName, String properties) {
        // For each property placeholder, replace with the actual value
        String result = properties;

        // Use Hackvertor's registry to get the list of available properties for this component
        List<String> availableProperties = Hackvertor.getFakerProperties(componentName);
        if (availableProperties == null) {
            return properties;
        }

        // For each available property, try to get its value and replace in the string
        for (String prop : availableProperties) {
            String propName = prop.substring(1); // Remove the $ prefix
            String value = getFakerPropertyValue(component, componentName, propName);
            if (value != null) {
                result = result.replace(prop, value);
            }
        }

        return result;
    }

    private static String getFakerPropertyValue(Object component, String componentName, String propertyName) {
        try {
            // Direct method calls based on component type and property name
            // This avoids reflection completely
            switch(componentName) {
                case "address":
                    com.github.javafaker.Address addr = (com.github.javafaker.Address) component;
                    switch(propertyName) {
                        case "buildingNumber": return addr.buildingNumber();
                        case "city": return addr.city();
                        case "cityName": return addr.cityName();
                        case "cityPrefix": return addr.cityPrefix();
                        case "citySuffix": return addr.citySuffix();
                        case "country": return addr.country();
                        case "countryCode": return addr.countryCode();
                        case "firstName": return addr.firstName();
                        case "fullAddress": return addr.fullAddress();
                        case "lastName": return addr.lastName();
                        case "latitude": return addr.latitude();
                        case "longitude": return addr.longitude();
                        case "secondaryAddress": return addr.secondaryAddress();
                        case "state": return addr.state();
                        case "stateAbbr": return addr.stateAbbr();
                        case "streetAddress": return addr.streetAddress();
                        case "streetAddressNumber": return addr.streetAddressNumber();
                        case "streetName": return addr.streetName();
                        case "streetPrefix": return addr.streetPrefix();
                        case "streetSuffix": return addr.streetSuffix();
                        case "timeZone": return addr.timeZone();
                        case "zipCode": return addr.zipCode();
                        case "zipCodePlus4": return addr.zipCodeByState(addr.stateAbbr());
                    }
                    break;
                case "ancient":
                    com.github.javafaker.Ancient ancient = (com.github.javafaker.Ancient) component;
                    switch(propertyName) {
                        case "god": return ancient.god();
                        case "hero": return ancient.hero();
                        case "primordial": return ancient.primordial();
                        case "titan": return ancient.titan();
                    }
                    break;
                case "animal":
                    com.github.javafaker.Animal animal = (com.github.javafaker.Animal) component;
                    if ("name".equals(propertyName)) return animal.name();
                    break;
                case "app":
                    com.github.javafaker.App app = (com.github.javafaker.App) component;
                    switch(propertyName) {
                        case "author": return app.author();
                        case "name": return app.name();
                        case "version": return app.version();
                    }
                    break;
                case "artist":
                    com.github.javafaker.Artist artist = (com.github.javafaker.Artist) component;
                    if ("name".equals(propertyName)) return artist.name();
                    break;
                case "avatar":
                    com.github.javafaker.Avatar avatar = (com.github.javafaker.Avatar) component;
                    if ("image".equals(propertyName)) return avatar.image();
                    break;
                case "aviation":
                    com.github.javafaker.Aviation aviation = (com.github.javafaker.Aviation) component;
                    switch(propertyName) {
                        case "aircraft": return aviation.aircraft();
                        case "airline": return null; // airline method doesn't exist in javafaker
                        case "airport": return aviation.airport();
                        case "METAR": return aviation.METAR();
                    }
                    break;
                case "book":
                    com.github.javafaker.Book book = (com.github.javafaker.Book) component;
                    switch(propertyName) {
                        case "author": return book.author();
                        case "genre": return book.genre();
                        case "publisher": return book.publisher();
                        case "title": return book.title();
                    }
                    break;
                case "bool":
                    com.github.javafaker.Bool bool = (com.github.javafaker.Bool) component;
                    if ("bool".equals(propertyName)) return String.valueOf(bool.bool());
                    break;
                case "business":
                    com.github.javafaker.Business business = (com.github.javafaker.Business) component;
                    switch(propertyName) {
                        case "creditCardExpiry": return business.creditCardExpiry();
                        case "creditCardNumber": return business.creditCardNumber();
                        case "creditCardType": return business.creditCardType();
                    }
                    break;
                case "code":
                    com.github.javafaker.Code code = (com.github.javafaker.Code) component;
                    switch(propertyName) {
                        case "asin": return code.asin();
                        case "ean13": return code.ean13();
                        case "ean8": return code.ean8();
                        case "gtin13": return code.gtin13();
                        case "gtin8": return code.gtin8();
                        case "imei": return code.imei();
                        case "isbn10": return code.isbn10();
                        case "isbn13": return code.isbn13();
                        case "isbnGroup": return code.isbnGroup();
                        case "isbnGs1": return code.isbnGs1();
                        case "isbnRegistrant": return code.isbnRegistrant();
                    }
                    break;
                case "currency":
                    com.github.javafaker.Currency currency = (com.github.javafaker.Currency) component;
                    switch(propertyName) {
                        case "code": return currency.code();
                        case "name": return currency.name();
                    }
                    break;
                case "color":
                    com.github.javafaker.Color color = (com.github.javafaker.Color) component;
                    switch(propertyName) {
                        case "hex": return color.hex();
                        case "name": return color.name();
                    }
                    break;
                case "commerce":
                    com.github.javafaker.Commerce commerce = (com.github.javafaker.Commerce) component;
                    switch(propertyName) {
                        case "color": return commerce.color();
                        case "department": return commerce.department();
                        case "material": return commerce.material();
                        case "price": return commerce.price();
                        case "productName": return commerce.productName();
                        case "promotionCode": return commerce.promotionCode();
                    }
                    break;
                case "company":
                    com.github.javafaker.Company company = (com.github.javafaker.Company) component;
                    switch(propertyName) {
                        case "bs": return company.bs();
                        case "buzzword": return company.buzzword();
                        case "catchPhrase": return company.catchPhrase();
                        case "industry": return company.industry();
                        case "logo": return company.logo();
                        case "name": return company.name();
                        case "profession": return company.profession();
                        case "suffix": return company.suffix();
                        case "url": return company.url();
                    }
                    break;
                case "crypto":
                    com.github.javafaker.Crypto crypto = (com.github.javafaker.Crypto) component;
                    switch(propertyName) {
                        case "md5": return crypto.md5();
                        case "sha1": return crypto.sha1();
                        case "sha256": return crypto.sha256();
                        case "sha512": return crypto.sha512();
                    }
                    break;
                case "date":
                    com.github.javafaker.DateAndTime date = (com.github.javafaker.DateAndTime) component;
                    if ("birthday".equals(propertyName)) return date.birthday().toString();
                    break;
                case "demographic":
                    com.github.javafaker.Demographic demographic = (com.github.javafaker.Demographic) component;
                    switch(propertyName) {
                        case "demonym": return demographic.demonym();
                        case "educationalAttainment": return demographic.educationalAttainment();
                        case "maritalStatus": return demographic.maritalStatus();
                        case "race": return demographic.race();
                        case "sex": return demographic.sex();
                    }
                    break;
                case "educator":
                    com.github.javafaker.Educator educator = (com.github.javafaker.Educator) component;
                    switch(propertyName) {
                        case "campus": return educator.campus();
                        case "course": return educator.course();
                        case "secondarySchool": return educator.secondarySchool();
                        case "university": return educator.university();
                    }
                    break;
                case "file":
                    com.github.javafaker.File file = (com.github.javafaker.File) component;
                    switch(propertyName) {
                        case "extension": return file.extension();
                        case "fileName": return file.fileName();
                        case "mimeType": return file.mimeType();
                    }
                    break;
                case "finance":
                    com.github.javafaker.Finance finance = (com.github.javafaker.Finance) component;
                    switch(propertyName) {
                        case "bic": return finance.bic();
                        case "creditCard": return finance.creditCard();
                        case "iban": return finance.iban();
                    }
                    break;
                case "food":
                    com.github.javafaker.Food food = (com.github.javafaker.Food) component;
                    switch(propertyName) {
                        case "dish": return food.dish();
                        case "fruit": return food.fruit();
                        case "ingredient": return food.ingredient();
                        case "measurement": return food.measurement();
                        case "spice": return food.spice();
                        case "sushi": return food.sushi();
                        case "vegetable": return food.vegetable();
                    }
                    break;
                case "hacker":
                    com.github.javafaker.Hacker hacker = (com.github.javafaker.Hacker) component;
                    switch(propertyName) {
                        case "abbreviation": return hacker.abbreviation();
                        case "adjective": return hacker.adjective();
                        case "ingverb": return hacker.ingverb();
                        case "noun": return hacker.noun();
                        case "verb": return hacker.verb();
                    }
                    break;
                case "idNumber":
                    com.github.javafaker.IdNumber idNumber = (com.github.javafaker.IdNumber) component;
                    switch(propertyName) {
                        case "invalid": return idNumber.invalid();
                        case "invalidSvSeSsn": return idNumber.invalidSvSeSsn();
                        case "ssnValid": return idNumber.ssnValid();
                        case "valid": return idNumber.valid();
                        case "validSvSeSsn": return idNumber.validSvSeSsn();
                    }
                    break;
                case "internet":
                    com.github.javafaker.Internet internet = (com.github.javafaker.Internet) component;
                    switch(propertyName) {
                        case "avatar": return internet.avatar();
                        case "domainName": return internet.domainName();
                        case "domainSuffix": return internet.domainSuffix();
                        case "domainWord": return internet.domainWord();
                        case "emailAddress": return internet.emailAddress();
                        case "image": return internet.image();
                        case "ipV4Address": return internet.ipV4Address();
                        case "ipV4Cidr": return internet.ipV4Cidr();
                        case "ipV6Address": return internet.ipV6Address();
                        case "ipV6Cidr": return internet.ipV6Cidr();
                        case "macAddress": return internet.macAddress();
                        case "password": return internet.password();
                        case "privateIpV4Address": return internet.privateIpV4Address();
                        case "publicIpV4Address": return internet.publicIpV4Address();
                        case "safeEmailAddress": return internet.safeEmailAddress();
                        case "slug": return internet.slug();
                        case "url": return internet.url();
                        case "userAgent": return internet.userAgent(null);
                        case "uuid": return internet.uuid();
                    }
                    break;
                case "job":
                    com.github.javafaker.Job job = (com.github.javafaker.Job) component;
                    switch(propertyName) {
                        case "field": return job.field();
                        case "keySkills": return job.keySkills();
                        case "position": return job.position();
                        case "seniority": return job.seniority();
                        case "title": return job.title();
                    }
                    break;
                case "lorem":
                    com.github.javafaker.Lorem lorem = (com.github.javafaker.Lorem) component;
                    switch(propertyName) {
                        case "character": return String.valueOf(lorem.character());
                        case "characters": return lorem.characters();
                        case "fixedString": return lorem.fixedString(10);
                        case "paragraph": return lorem.paragraph();
                        case "sentence": return lorem.sentence();
                        case "word": return lorem.word();
                    }
                    break;
                case "music":
                    com.github.javafaker.Music music = (com.github.javafaker.Music) component;
                    switch(propertyName) {
                        case "chord": return music.chord();
                        case "genre": return music.genre();
                        case "instrument": return music.instrument();
                        case "key": return music.key();
                    }
                    break;
                case "name":
                    com.github.javafaker.Name name = (com.github.javafaker.Name) component;
                    switch(propertyName) {
                        case "bloodGroup": return name.bloodGroup();
                        case "firstName": return name.firstName();
                        case "fullName": return name.fullName();
                        case "lastName": return name.lastName();
                        case "name": return name.name();
                        case "nameWithMiddle": return name.nameWithMiddle();
                        case "prefix": return name.prefix();
                        case "suffix": return name.suffix();
                        case "title": return name.title();
                        case "username": return name.username();
                    }
                    break;
                case "nation":
                    com.github.javafaker.Nation nation = (com.github.javafaker.Nation) component;
                    switch(propertyName) {
                        case "capitalCity": return nation.capitalCity();
                        case "flag": return nation.flag();
                        case "language": return nation.language();
                        case "nationality": return nation.nationality();
                    }
                    break;
                case "number":
                    com.github.javafaker.Number number = (com.github.javafaker.Number) component;
                    switch(propertyName) {
                        case "digit": return String.valueOf(number.digit());
                        case "digits": return number.digits(5);
                        case "negative": return String.valueOf(number.numberBetween(Integer.MIN_VALUE, -1));
                        case "positive": return String.valueOf(number.numberBetween(1, Integer.MAX_VALUE));
                    }
                    break;
                case "options":
                    com.github.javafaker.Options options = (com.github.javafaker.Options) component;
                    if ("option".equals(propertyName)) return options.option("option1", "option2", "option3");
                    break;
                case "phoneNumber":
                    com.github.javafaker.PhoneNumber phoneNumber = (com.github.javafaker.PhoneNumber) component;
                    switch(propertyName) {
                        case "cellPhone": return phoneNumber.cellPhone();
                        case "phoneNumber": return phoneNumber.phoneNumber();
                        case "phoneNumberInternational": return phoneNumber.phoneNumber(); // Use phoneNumber as fallback
                        case "phoneNumberNational": return phoneNumber.phoneNumber(); // Use phoneNumber as fallback
                        case "phoneNumberWithExtension": return phoneNumber.subscriberNumber(5);
                        case "tollFreePhoneNumber": return phoneNumber.cellPhone(); // No direct toll-free method
                    }
                    break;
                case "slackEmoji":
                    com.github.javafaker.SlackEmoji slackEmoji = (com.github.javafaker.SlackEmoji) component;
                    switch(propertyName) {
                        case "activity": return slackEmoji.activity();
                        case "celebration": return slackEmoji.celebration();
                        case "custom": return slackEmoji.custom();
                        case "emoji": return slackEmoji.emoji();
                        case "foodAndDrink": return slackEmoji.foodAndDrink();
                        case "nature": return slackEmoji.nature();
                        case "people": return slackEmoji.people();
                    }
                    break;
                case "space":
                    com.github.javafaker.Space space = (com.github.javafaker.Space) component;
                    switch(propertyName) {
                        case "agency": return space.agency();
                        case "agencyAbbreviation": return space.agencyAbbreviation();
                        case "company": return space.company();
                        case "constellation": return space.constellation();
                        case "distanceMeasurement": return space.distanceMeasurement();
                        case "galaxy": return space.galaxy();
                        case "meteorite": return space.meteorite();
                        case "moon": return space.moon();
                        case "nasaSpaceCraft": return space.nasaSpaceCraft();
                        case "nebula": return space.nebula();
                        case "planet": return space.planet();
                        case "star": return space.star();
                        case "starCluster": return space.starCluster();
                    }
                    break;
                case "stock":
                    com.github.javafaker.Stock stock = (com.github.javafaker.Stock) component;
                    switch(propertyName) {
                        case "nsdqSymbol": return stock.nsdqSymbol();
                        case "nyseSymbol": return stock.nyseSymbol();
                    }
                    break;
                case "team":
                    com.github.javafaker.Team team = (com.github.javafaker.Team) component;
                    switch(propertyName) {
                        case "creature": return team.creature();
                        case "name": return team.name();
                        case "sport": return team.sport();
                        case "state": return team.state();
                    }
                    break;
                case "university":
                    com.github.javafaker.University university = (com.github.javafaker.University) component;
                    switch(propertyName) {
                        case "name": return university.name();
                        case "prefix": return university.prefix();
                        case "suffix": return university.suffix();
                    }
                    break;
                case "weather":
                    com.github.javafaker.Weather weather = (com.github.javafaker.Weather) component;
                    switch(propertyName) {
                        case "description": return weather.description();
                        case "temperatureCelsius": return weather.temperatureCelsius();
                        case "temperatureFahrenheit": return weather.temperatureFahrenheit();
                    }
                    break;
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    static String sha1(String str) {
        return DigestUtils.sha1Hex(str);
    }

    static String sha224(String message) {
        SHA224Digest digest = new SHA224Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String sha256(String str) {
        return DigestUtils.sha256Hex(str);
    }

    static String sha384(String str) {
        return DigestUtils.sha384Hex(str);
    }

    static String sha512(String str) {
        return DigestUtils.sha512Hex(str);
    }

    static String sha3(String message) {
        SHA3Digest digest = new SHA3Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String sha3_224(String message) {
        SHA3Digest digest = new SHA3Digest(224);
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String sha3_256(String message) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String sha3_384(String message) {
        SHA3Digest digest = new SHA3Digest(384);
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String sha3_512(String message) {
        SHA3Digest digest = new SHA3Digest(512);
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String skein_256_128(String message) {
        Skein.Digest_256_128 digest = new Skein.Digest_256_128();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_256_160(String message) {
        Skein.Digest_256_160 digest = new Skein.Digest_256_160();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_256_224(String message) {
        Skein.Digest_256_224 digest = new Skein.Digest_256_224();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_256_256(String message) {
        Skein.Digest_256_256 digest = new Skein.Digest_256_256();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_128(String message) {
        Skein.Digest_512_128 digest = new Skein.Digest_512_128();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_160(String message) {
        Skein.Digest_512_160 digest = new Skein.Digest_512_160();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_224(String message) {
        Skein.Digest_512_224 digest = new Skein.Digest_512_224();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_256(String message) {
        Skein.Digest_512_256 digest = new Skein.Digest_512_256();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_384(String message) {
        Skein.Digest_512_384 digest = new Skein.Digest_512_384();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_512_512(String message) {
        Skein.Digest_512_512 digest = new Skein.Digest_512_512();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_1024_384(String message) {
        Skein.Digest_1024_384 digest = new Skein.Digest_1024_384();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_1024_512(String message) {
        Skein.Digest_1024_512 digest = new Skein.Digest_1024_512();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String skein_1024_1024(String message) {
        Skein.Digest_1024_1024 digest = new Skein.Digest_1024_1024();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
    }

    static String sm3(String message) {
        SM3Digest digest = new SM3Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String tiger(String message) {
        TigerDigest digest = new TigerDigest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String md2(String str) {
        return DigestUtils.md2Hex(str);
    }

    static String md5(String str) {
        return DigestUtils.md5Hex(str);
    }

    static String md4(String message) {
        MD4Digest digest = new MD4Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] md4Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md4Bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes);
    }

    static String gost3411(String message) {
        GOST3411Digest digest = new GOST3411Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String ripemd128(String message) {
        RIPEMD128Digest digest = new RIPEMD128Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String ripemd160(String message) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String ripemd256(String message) {
        RIPEMD256Digest digest = new RIPEMD256Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String ripemd320(String message) {
        RIPEMD320Digest digest = new RIPEMD320Digest();
        digest.update(message.getBytes(), 0, message.getBytes().length);
        byte[] bytes = new byte[digest.getDigestSize()];
        digest.doFinal(bytes, 0);
        return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
    }

    static String whirlpool(String message) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("WHIRLPOOL", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace(); //Unlikely to happen
            return "";
        }
        byte[] result = digest.digest(message.getBytes());
        return new String(Hex.encode(result));
    }

    static String reverse(String str) {
        return new StringBuilder(str).reverse().toString();
    }

    static String len(String str) {
        return Integer.toString(str.length());
    }

    static String find(String str, String find, int group) {
        java.util.List<String> allMatches = new ArrayList<String>();
        try {
            Matcher m = Pattern.compile(find).matcher(str);
            while (m.find()) {
                if(group == -1) {
                    allMatches.add(m.group());
                } else {
                    allMatches.add(m.group(group));
                }
            }
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        return StringUtils.join(allMatches, ",");
    }

    static String replace(String str, String find, String replace) {
        return str.replace(find, replace);
    }

    static String regex_replace(String str, String find, String replace) {
        String output = "";
        try {
            output = str.replaceAll(find, replace.replace("\\", "\\\\"));
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        return output;
    }

    static String substring(String str, int start, int end) {
        try {
            return str.substring(start, end);
        } catch (StringIndexOutOfBoundsException e) {
            return "Invalid index:"+e;
        }
    }

    static String repeat(String str, int amount) {
        if (amount > 0 && amount < 10000) {
            return str.repeat(amount);
        }
        return "";
    }

    static String split_join(String str, String splitChar, String joinChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        return StringUtils.join(chars, joinChar);
    }

    static double is_like_english(String str) {
        if(ngrams == null) {
            try {
                ngrams = new Ngrams("/quadgrams.txt");
            } catch (IOException e) {
                stderr.println(e.getMessage());
            }
        }
        ngrams.setInput(str);
        return ngrams.getScore();
    }

    static double index_of_coincidence(String str) {
        Map<Integer, Integer> charCounter = new HashMap<Integer, Integer>();
        for (int i = 0; i <= 0xff; i++) {
            charCounter.put(i, 0);
        }
        for (int i = 0; i < str.length(); i++) {
            int cp = str.codePointAt(i);
            charCounter.put(cp, charCounter.get(cp) + 1);

        }
        double sum = 0;
        int total = str.length();
        for (int i = 0; i <= 0xff; i++) {
            sum = sum + charCounter.get(i) * (i - 1 < 0 ? 0 : charCounter.get(i - 1));
        }
        double ic = sum / (total * (total - 1));
        return ic;
    }

    static int getGCD(int n1, int n2) {
        if (n2 == 0) {
            return n1;
        }
        return getGCD(n2, n1 % n2);
    }

    static <K, V extends Comparable<V>> Map<K, V> sortByValuesDesc(final Map<K, V> map) {
        Comparator<K> valueComparator =
                new Comparator<K>() {
                    public int compare(K k1, K k2) {
                        int compare =
                                map.get(k2).compareTo(map.get(k1));
                        if (compare == 0)
                            return 1;
                        else
                            return compare;
                    }
                };

        Map<K, V> sortedByValues =
                new TreeMap<K, V>(valueComparator);
        sortedByValues.putAll(map);
        return sortedByValues;
    }

    static <K, V extends Comparable<V>> Map<K, V> sortByValuesAsc(final Map<K, V> map) {
        Comparator<K> valueComparator =
                new Comparator<K>() {
                    public int compare(K k1, K k2) {
                        int compare =
                                map.get(k1).compareTo(map.get(k2));
                        if (compare == 0)
                            return 1;
                        else
                            return compare;
                    }
                };

        Map<K, V> sortedByValues =
                new TreeMap<K, V>(valueComparator);
        sortedByValues.putAll(map);
        return sortedByValues;
    }

    static Boolean isBase64(String str, Boolean checkStart) {
        return Pattern.compile((checkStart ? "^" : "") + "[a-zA-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0;
    }
    static String auto_decode(String str) {
        return auto_decode_decrypt(str, true);
    }

    public static String auto_decode_no_decrypt(String str) {
        return auto_decode_decrypt(str, false);
    }

    static String auto_decode_decrypt(String str, Boolean decrypt) {
        int repeats = 20;
        int repeat = 0;
        boolean matched;
        String test;
        String encodingOpeningTags = "";
        String encodingClosingTags = "";
        String tag = "";
        do {
            String startStr = str;
            matched = false;
            int tagNo = new Random().nextInt(10000);
            if (Pattern.compile("^\\x1f\\x8b\\x08").matcher(str).find()) {
                str = gzip_decompress(str);
                matched = true;
                encodingOpeningTags += "<@gzip_compress>";
                encodingClosingTags = "</@gzip_compress>" + encodingClosingTags;
            }
            if (Pattern.compile("[01]{4,}\\s+[01]{4,}").matcher(str).find()) {
                str = bin2ascii(str);
                matched = true;
                encodingOpeningTags += "<@ascii2bin>";
                encodingClosingTags = "</@ascii2bin>" + encodingClosingTags;
            }
            if (Pattern.compile("(?:[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = hex2ascii(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    encodingOpeningTags += "<@ascii2hex(\" \")>";
                    encodingClosingTags = "</@ascii2hex>" + encodingClosingTags;
                    repeat++;
                    continue;
                }
            }
            if (Pattern.compile("^[0-9a-fA-F]+$").matcher(str).find() && str.length() % 2 == 0) {
                str = hex2ascii(str);
                matched = true;
                encodingOpeningTags += "<@ascii2hex(\"\")>";
                encodingClosingTags = "</@ascii2hex>" + encodingClosingTags;
            }
            if (!Pattern.compile("[^\\d,\\s]").matcher(str).find() && Pattern.compile("\\d+[,\\s]+").matcher(str).find()) {
                str = from_charcode(str);
                matched = true;
                encodingOpeningTags += "<@to_charcode>";
                encodingClosingTags = "</@to_charcode>" + encodingClosingTags;
            }
            if (Pattern.compile("(?:\\\\[0]{0,4}[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = decode_css_escapes(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@css_escapes>";
                    encodingClosingTags = "</@css_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\x[0-9a-f]{2}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@hex_escapes>";
                    encodingClosingTags = "</@hex_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\[0-9]{1,3}").matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@octal_escapes>";
                    encodingClosingTags = "</@octal_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\u[0-9a-f]{4}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@unicode_escapes>";
                    encodingClosingTags = "</@unicode_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("&[a-zA-Z]+;", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags += "<@html_entities>";
                encodingClosingTags = "</@html_entities>" + encodingClosingTags;
            }
            if (Pattern.compile("&#x?[0-9a-f]+;?", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags += "<@hex_entities>";
                encodingClosingTags = "</@hex_entities>" + encodingClosingTags;
            }
            if (Pattern.compile("%[0-9a-f]{2}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                boolean plus = false;
                if (str.contains("+")) {
                    plus = true;
                }
                str = decode_url(str);
                matched = true;
                if (plus) {
                    tag = "urldecode";
                    encodingOpeningTags += "<@urlencode>";
                    encodingClosingTags = "</@urlencode>" + encodingClosingTags;
                } else {
                    tag = "urlencode_not_plus";
                    encodingOpeningTags += "<@urlencode_not_plus>";
                    encodingClosingTags = "</@urlencode_not_plus>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("^[a-zA-Z0-9\\-_.]+$", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                String[] parts = str.split("\\.");
                if (parts.length == 3 && !d_jwt_get_header(str).equals("Invalid token")) {
                    return d_jwt_get_header(str) + "\n" + d_jwt_get_payload(str) + "\n" + decode_base64url(parts[2]);
                }
            }
            if (isBase64(str, true)) {
                test = decode_base64(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base64";
                    encodingOpeningTags += "<@base64>";
                    encodingClosingTags = "</@base64>" + encodingClosingTags;
                }
            }

            if (Pattern.compile("[A-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0 && !matched) {
                test = decode_base32(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base32";
                    encodingOpeningTags += "<@base32>";
                    encodingClosingTags = "</@base32>" + encodingClosingTags;
                }
            }
            if (decrypt) {
                if (Pattern.compile("(?:[a-zA-Z]+[\\s,-]){2,}").matcher(str).find()) {
                    double total = 0;
                    double bestScore = -9999999;
                    int n = 0;
                    for (int i = 1; i <= 25; i++) {
                        String rotString = rotN(str, i);
                        double score = is_like_english(rotString);
                        total += score;
                        if (score > bestScore) {
                            bestScore = score;
                            n = i;
                        }
                    }
                    double average = (total / 25);
                    if ((((average - bestScore) / average) * 100) > 20) {
                        String originalString = str;
                        str = rotN(str, n);
                        matched = true;
                        tag = "rotN";
                        for (int i = 1; i <= 25; i++) {
                            if (rotN(str, i).equals(originalString)) {
                                n = i;
                                break;
                            }
                        }
                        encodingOpeningTags += "<@rotN(" + n + ")>";
                        encodingClosingTags = "</@rotN>" + encodingClosingTags;
                    }
                }
                if (Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
                    double total = 0;
                    double bestScore = -9999999;
                    int key1 = 0;
                    int key2 = 0;
                    int[] keyArray1 = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
                    int[] keyArray2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
                    for (int i = 0; i < keyArray1.length; i++) {
                        for (int j = 0; j < keyArray2.length; j++) {
                            String decodedString = affine_decrypt(str, keyArray1[i], keyArray2[j]);
                            double score = is_like_english(decodedString);
                            total += score;
                            if (score > bestScore) {
                                bestScore = score;
                                key1 = keyArray1[i];
                                key2 = keyArray2[j];
                            }
                        }
                    }
                    double average = (total / 25);
                    if ((((average - bestScore) / average) * 100) > 60 && (key1 != 1 && key2 != 0)) {
                        str = affine_decrypt(str, key1, key2);
                        matched = true;
                        tag = "affine";
                        encodingOpeningTags += "<@affine_encrypt(" + key1 + "," + key2 + ")>";
                        encodingClosingTags = "</@affine_encrypt>" + encodingClosingTags;
                    }
                }

                if (Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
                    String plaintext = atbash_decrypt(str);
                    if (is_like_english(plaintext) - is_like_english(str) >= 200) {
                        str = plaintext;
                        matched = true;
                        tag = "atbash";
                        encodingOpeningTags += "<@atbash_encrypt>";
                        encodingClosingTags = "</@atbash_encrypt>" + encodingClosingTags;
                    }
                }
                if (Pattern.compile("^[a-z]{10,}$").matcher(str).find()) {
                    double total = 0;
                    double bestScore = -9999999;
                    int n = 0;
                    double max = Math.floor(2 * str.length() - 1);
                    for (int i = 2; i < max; i++) {
                        String decodedString = rail_fence_decrypt(str, i);
                        double score = is_like_english(decodedString);
                        total += score;
                        if (score > bestScore) {
                            bestScore = score;
                            n = i;
                        }
                    }
                    double average = (total / max - 1);
                    if ((((average - bestScore) / average) * 100) > 20) {
                        str = rail_fence_decrypt(str, n);
                        matched = true;
                        tag = "rail_fence";
                        encodingOpeningTags += "<@rail_fence_encrypt(" + n + ")>";
                        encodingClosingTags = "</@rail_fence_encrypt>" + encodingClosingTags;
                    }
                }

                if (Pattern.compile("^[\\x00-\\xff]+$", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                    int lenGuess = guess_key_length(str);
                    test = xor_decrypt(str, lenGuess, false);
                    int alphaCount = test.replaceAll("[^a-zA-Z0-9]+", "").length();
                    int strLen = str.length();
                    float percent = (((float) alphaCount / strLen) * 100);
                    if (is_like_english(test) < is_like_english(str) && percent > 20) {
                        String key = xor_decrypt(str, lenGuess, true).replaceAll("\"", "\\\"");
                        str = test;
                        matched = true;
                        tag = "xor";
                        encodingOpeningTags += "<@xor(\"" + key + "\")>";
                        encodingClosingTags = "</@xor>" + encodingClosingTags;
                    }
                }
            }
            if (!matched || startStr.equals(str)) {
                break;
            }
            repeat++;
        } while (repeat < repeats);
        return encodingOpeningTags + str + encodingClosingTags;
    }

    static String range(String str, int from, int to, int step) {
        ArrayList<Integer> output = new ArrayList<Integer>();
        to++;
        if (from >= 0 && to - from <= 10000 && step > 0) {
            for (int i = from; i < to; i += step) {
                output.add(i);
            }
        }
        return StringUtils.join(output, ",");
    }

    static String total(String str) {
        String[] chars = str.split(",");
        int total = 0;
        for (int i = 0; i < chars.length; i++) {
            try {
                total += Integer.parseInt(chars[i]);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return Integer.toString(total);
    }

    static String arithmetic(String str, int amount, String operation, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        ArrayList<String> output = new ArrayList<>();
        int num = 0;
        for (int i = 0; i < chars.length; i++) {
            try {
                num = Integer.parseInt(chars[i]);
                switch (operation) {
                    case "+":
                        num = num + amount;
                        break;
                    case "-":
                        num = num - amount;
                        break;
                    case "/":
                        num = num / amount;
                        break;
                    case "*":
                        num = num * amount;
                        break;
                    case "%":
                        num = num % amount;
                        break;
                    case ">>":
                        num = num >> amount;
                        break;
                    case ">>>":
                        num = num >>> amount;
                        break;
                    case "<<":
                        num = num << amount;
                        break;
                }
                output.add("" + num);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(output, ",");
    }

    static String convert_base(String str, String splitChar, int from, int to) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = "" + Integer.toString(Integer.parseInt(chars[i], from), to);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String zeropad(String str, String splitChar, int amount) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        if (amount > 0 && amount < 10000) {
            for (int i = 0; i < chars.length; i++) {
                chars[i] = StringUtils.leftPad(chars[i], amount, '0');
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String uuid() {
        return UUID.randomUUID().toString();
    }

    static String eval_fromcharcode(String str) {
        return "eval(String.fromCharCode(" + to_charcode(str) + "))";
    }

    static String behavior(String str) {
        return "<PUBLIC:ATTACH EVENT=onload ONEVENT=" + str + " FOR=window />";
    }

    static String css_expression(String str) {
        return "xss:expression(open(" + str + "))";
    }

    static String datasrc(String str) {
        return "<xml ID=xss><x><B>&lt;IMG src=1 onerror=" + str + "&gt;</B></x></xml><SPAN DATASRC=#xss DATAFLD=B DATAFORMATAS=HTML></SPAN>";
    }

    static String iframe_data_url(String str) {
        return "<iframe src=data:text/html;base64," + base64Encode(str) + ">";
    }

    static String uppercase_script(String str) {
        return "<SVG><SCRIPT>" + dec_entities(str) + "</SCRIPT></SVG>";
    }

    static String script_data(String str) {
        return "<script src=data:;base64," + base64Encode(str) + "></script>";
    }

    static String throw_eval(String str) {
        String out = "window.onerror=eval;throw'=";
        for (int i = 0; i < str.length(); i++) {
            char chr = str.charAt(i);
            if (Character.isDigit(chr) || Character.isAlphabetic(chr)) {
                out += chr;
            } else {
                out += hex_escapes("" + chr);
            }
        }
        out += "'";
        return out;
    }

    static String iframe_src_doc(String str) {
        return "<iframe srcdoc=" + html5_entities(str) + "></iframe>";
    }

    static String template_eval(String str) {
        return "eval(`" + str.replaceAll("(.)", "$1\\${[]}") + "`)";
    }

    public static String python(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }

        try {
            String pythonModulePath = HackvertorExtension.generalSettings.getString("pythonModulePath");
            PythonInterpreter pythonInterpreter = new PythonInterpreter();
            pythonInterpreter.set("hackvertor", hackvertor);
            pythonInterpreter.set("input", input);
            pythonInterpreter.set("executionKey", executionKey);
            pythonInterpreter.set("variableMap", variableMap);
            pythonInterpreter.set("customTags", customTags);
            for (Map.Entry<String, String> entry : variableMap.entrySet()) {
                String name = entry.getKey();
                Object value = entry.getValue();
                if (!name.isEmpty()) {
                    pythonInterpreter.set(name, value);
                }
            }
            if (customTagOptions != null) {
                JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
                int numberOfArgs = customTag.getInt("numberOfArgs");
                if (numberOfArgs == 1) {
                    pythonInterpreter.set(customTag.getString("argument1"), customTagOptions.get("param1"));
                }
                if (numberOfArgs == 2) {
                    pythonInterpreter.set(customTag.getString("argument1"), customTagOptions.get("param1"));
                    pythonInterpreter.set(customTag.getString("argument2"), customTagOptions.get("param2"));
                }
            }

            if (code.endsWith(".py")) {
                pythonInterpreter.execfile(code);
            } else {
                String initCode = "import sys\n" +
                "from burp.hv import HackvertorExtension\n" +
                "class StreamWrapper(object):\n" +
                "   def __init__(self, wrapped):\n" +
                "       self.__wrapped = wrapped\n" +
                "   def __getattr__(self, name):\n" +
                "       return getattr(self.__wrapped, name)\n" +
                "   def write(self, text):\n" +
                "       HackvertorExtension.print(text)\n" +
                "orig_stdout = sys.stdout\n" +
                "sys.stdout = StreamWrapper(orig_stdout)\n" +
                "from burp.hv import Convertors\n" +
                        (!pythonModulePath.isEmpty() ? "sys.path.insert(0, '"+pythonModulePath.replace("\\", "\\\\")   // backslashes first
                                .replace("'", "\\'")+"')\n" : "")
                        +
                "def convert(input):\n" +
                "   return Convertors.weakConvert(variableMap, customTags, input, hackvertor)\n" +
                "\n";
                pythonInterpreter.exec(initCode + code);
            }
            PyObject output = pythonInterpreter.get("output");
            if (output != null) {
                return output.asString();
            } else {
                return "No output variable defined";
            }
        } catch (PyException e) {
            return "Invalid Python code:" + e;
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            return "Error loading settings:" + e;
        } catch (Exception e) {
            return "Unable to parse Python:" + e;
        }
    }

    public static String java(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        Interpreter javaInterpreter = new Interpreter();
        try {
            javaInterpreter.set("input", input);
            javaInterpreter.set("hackvertor", hackvertor);
            javaInterpreter.set("variableMap", variableMap);
            javaInterpreter.set("executionKey", executionKey);
            javaInterpreter.set("customTags", customTags);
            String initCode = "import burp.hv.Convertors;\n" +
                    "public String convert(String input) {\n" +
                    "   return Convertors.weakConvert(variableMap, customTags, input, hackvertor);\n" +
                    "}\n";


            for (Map.Entry<String, String> entry : variableMap.entrySet()) {
                String name = entry.getKey();
                Object value = entry.getValue();
                if (name.length() > 0) {
                    javaInterpreter.set(name, value);
                }
            }
            if (customTagOptions != null) {
                JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
                int numberOfArgs = customTag.getInt("numberOfArgs");
                if (numberOfArgs == 1) {
                    javaInterpreter.set(customTag.getString("argument1"), customTagOptions.get("param1"));
                }
                if (numberOfArgs == 2) {
                    javaInterpreter.set(customTag.getString("argument1"), customTagOptions.get("param1"));
                    javaInterpreter.set(customTag.getString("argument2"), customTagOptions.get("param2"));
                }
            }
            if (code.endsWith(".java")) {
                javaInterpreter.source(code);
            } else {
                javaInterpreter.eval(initCode + code);
            }
            return javaInterpreter.get("output").toString();
        } catch (EvalError | IOException e) {
            return "Unable to parse Java:" + e.toString();
        } catch (NullPointerException e) {
            return "Unable to get output. Make sure you have defined an output variable:" + e.toString();
        } catch (Exception | Error e ) {
            return "Unable to parse Java:" + e.toString();
        }
    }

    public static String ai_tag(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags, Hackvertor hackvertor, double temperature, boolean bypassRateLimit) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }

        boolean allowAiTags;
        try {
            allowAiTags = generalSettings.getBoolean("allowAiTags");
            if(!allowAiTags) {
                return "You have disabled AI tags in settings";
            }
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            callbacks.printError("Error loading settings: "  + e);
            throw new RuntimeException(e);
        }

        AI ai = new AI();
        ai.setBypassRateLimit(bypassRateLimit);
        String defaultInstructions = """
                Do not describe what you are doing just display the results.
                Be as concise as possible. 
                Do not prefix with anything just display the results.               
                """;

        String parameters = "";
        try {
            ai.setTemperature(temperature);
            if (customTagOptions != null) {
                JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
                int numberOfArgs = customTag.getInt("numberOfArgs");
                if(customTag.getString("argument1").equals("temperature")) {
                    ai.setTemperature(Double.parseDouble(customTagOptions.get("param1").toString()));
                } else if(!customTag.getString("argument1").isEmpty()) {
                    parameters += customTag.getString("argument1") + " has been supplied by the user and is " + customTagOptions.get("param1")+".";
                }
                if (numberOfArgs == 2) {
                    parameters += customTag.getString("argument2") + " has been supplied by the user and is " + customTagOptions.get("param2")+".";
                }
            }
            ai.setSystemMessage(defaultInstructions + parameters + code);
            ai.setPrompt(input);
            return ai.execute().trim();
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            return "Error calling the AI API:" + writer;
        }
    }

    public static String groovy(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        Binding data = new Binding();
        GroovyShell shell = new GroovyShell(data);
        data.setProperty("input", input);
        data.setVariable("hackvertor", hackvertor);
        data.setVariable("variableMap", variableMap);
        data.setVariable("executionKey", executionKey);
        data.setVariable("customTags", customTags);
        String initCode = "" +
                "public String convert(String input) {\n" +
                "   return Convertors.weakConvert(variableMap, customTags, input, hackvertor);\n" +
                "}\n";
        try {
            if (code.endsWith(".groovy")) {
                shell.evaluate(new FileReader(code));
            } else {
                shell.evaluate(initCode + code);
            }
        } catch (FileNotFoundException | CompilationFailedException e) {
            return "Unable to parse Groovy:" + e.toString();
        }
        return shell.getVariable("output").toString();
    }
    public static String javascript(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags, Hackvertor hackvertor) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        try {
            Context context = Context.newBuilder("js").allowIO(true).allowHostAccess(HostAccess.ALL).build();
            context.getBindings("js").putMember("input", input);
            context.getBindings("js").putMember("executionKey", executionKey);
            context.getBindings("js").putMember("atob", (EmitReturn<String>) Convertors::decode_base64);
            context.getBindings("js").putMember("btoa", (EmitReturn<String>) Convertors::base64Encode);
            context.getBindings("js").putMember("convert", (EmitReturn<String>) (tagInput) -> Convertors.weakConvert(variableMap, customTags, tagInput, hackvertor));

            for (Map.Entry<String, String> entry : variableMap.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue();
                if (name.length() > 0) {
                    if (value.matches("^\\d+$") || value.matches("^0x[0-9a-fA-F]+$")) {
                        context.getBindings("js").putMember(name, Integer.parseInt(value));
                    } else {
                        context.getBindings("js").putMember(name, value);
                    }
                }
            }

            if (customTagOptions != null) {
                JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
                int numberOfArgs = customTag.getInt("numberOfArgs");
                if (numberOfArgs == 1) {
                    String name = customTag.getString("argument1");
                    String value = customTagOptions.get("param1").toString();
                    if (value.matches("^\\d+$") || value.matches("^0x[0-9a-fA-F]+$")) {
                        context.getBindings("js").putMember(name, Integer.parseInt(value));
                    } else {
                        context.getBindings("js").putMember(name, value);
                    }
                }
                if (numberOfArgs == 2) {
                    String argument1Name = customTag.getString("argument1");
                    String param1Value = customTagOptions.get("param1").toString();
                    if (param1Value.matches("^\\d+$") || param1Value.matches("^0x[0-9a-fA-F]+$")) {
                        context.getBindings("js").putMember(argument1Name, Integer.parseInt(param1Value));
                    } else {
                        context.getBindings("js").putMember(argument1Name, param1Value);
                    }
                    String argument2Name = customTag.getString("argument2");
                    String param2Value = customTagOptions.get("param2").toString();
                    if (param2Value.matches("^\\d+$") || param2Value.matches("^0x[0-9a-fA-F]+$")) {
                        context.getBindings("js").putMember(argument2Name, Integer.parseInt(param2Value));
                    } else {
                        context.getBindings("js").putMember(argument2Name, param2Value);
                    }
                }
            }

            if (code.endsWith(".js")) {
                return context.eval("js", new String(Files.readAllBytes(Paths.get(code)), StandardCharsets.UTF_8)).toString();
            } else {
                return context.eval("js", code).toString();
            }
        } catch(UnsatisfiedLinkError | NoClassDefFoundError | InternalError e) {
            return "Unfortunately you have to restart Burp now to make JavaScript tags work. This happens when reloading the extension.";
        } catch (Throwable e) {
            return "Exception:" + e;
        }
    }
    static String system(String cmd, Boolean enabled, String executionKey) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(!enabled) {
           return "The system command is disabled until you change the parameter to true.";
        }
        if(cmd.isEmpty()) {
            return "No command specified";
        }
        Runtime r = Runtime.getRuntime();
        Process p = null;
        try {
            p = r.exec(cmd);
        } catch (IOException e) {
            return "Failed to execute command:"+e;
        }
        try {
            boolean finished = p.waitFor(60, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return "Command execution timed out after 60 seconds";
            }
        } catch (InterruptedException e) {
            p.destroyForcibly();
            return "InterruptedException"+e;
        }
        BufferedReader b = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line = "";
        String lineSep = System.getProperty("line.separator");
        while (true) {
            try {
                if (!((line = b.readLine()) != null)) break;
            } catch (IOException e) {
                return "Failed to read output:"+e;
            }
            output.append(line);
            output.append(lineSep);
        }
        try {
            b.close();
        } catch (IOException e) {
            return "Failed to close buffered reader:" + e;
        }
        return output.toString();
    }

    @FunctionalInterface
    public interface EmitReturn<T> {
        @HostAccess.Export
        String emit(T type);
    }

    static String read_url(String input, String charset, Boolean enabled, String executionKey) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(!charset.equalsIgnoreCase("UTF-8")) {
            input = convertCharset(input, charset);
        }
        if(!enabled) {
           return "The read url command is disabled until you change the parameter to true.";
        }
        URL url = null;
        try {
            url = new URL(input);
        } catch (MalformedURLException e) {
            return "Malformed URL:" + e;
        }
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setReadTimeout(60);
            connection.connect();
            BufferedReader br = null;
            if (100 <= connection.getResponseCode() && connection.getResponseCode() <= 399) {
                br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            } else {
                br = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            }
            return br.lines().collect(Collectors.joining());
        } catch (IOException e) {
            return "Unable to get response";
        }
    }

    static String read_file(String input, String charset, Boolean enabled, String executionKey) {
        String errorMessage = CustomTags.checkTagExecutionPermissions(executionKey);
        if(errorMessage != null) {
            return errorMessage;
        }
        if(!charset.equalsIgnoreCase("UTF-8")) {
            input = convertCharset(input, charset);
        }
        if(!enabled) {
           return "The read file command is disabled until you change the parameter to true.";
        }
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get(input));
            return new String(fileContent, charset);
        } catch (IOException e) {
            return "Unable to read file: " + e.getMessage();
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
}
