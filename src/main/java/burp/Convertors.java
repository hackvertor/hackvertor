package burp;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.util.encoders.Hex;
import org.brotli.dec.BrotliInputStream;
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
import org.unbescape.javascript.JavaScriptEscape;
import org.unbescape.javascript.JavaScriptEscapeLevel;
import org.unbescape.javascript.JavaScriptEscapeType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.IntStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static burp.BurpExtender.*;
import static burp.BurpExtender.tagCodeExecutionKey;

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
        return args.get(pos);
    }

    public static Integer getInt(ArrayList<String> args, Integer pos) {
        Integer output;
        output = 0;
        if (args.size() < pos + 1) {
            return 0;
        }
        if (args.get(pos).contains("0x")) {
            try {
                return Integer.parseInt(args.get(pos).replaceAll("^0x", ""), 16);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        try {
            output = Integer.parseInt(args.get(pos));
        } catch (NumberFormatException e) {
            stderr.println(e.getMessage());
        }
        return output;
    }

    public static String callTag(HashMap<String, String> variableMap, JSONArray customTags, String tag, String output, ArrayList<String> arguments) {
        switch (tag) {
            default:
                if (tag.startsWith("_")) {
                    for (int i = 0; i < customTags.length(); i++) {
                        JSONObject customTag = (JSONObject) customTags.get(i);
                        String customTagName = customTag.getString("tagName");
                        int numberOfArgs = 0;
                        if (customTag.has("numberOfArgs")) {
                            numberOfArgs = customTag.getInt("numberOfArgs");
                        }
                        String eKey;
                        JSONObject customTagOptions = new JSONObject();
                        customTagOptions.put("customTag", customTag);
                        if (numberOfArgs == 0) {
                            eKey = getString(arguments, 0);
                            customTagOptions = null;
                        } else if (numberOfArgs == 1) {
                            if (customTag.getString("argument1Type").equals("String")) {
                                customTagOptions.put("param1", getString(arguments, 0));
                            } else if (customTag.getString("argument1Type").equals("Number")) {
                                customTagOptions.put("param1", getInt(arguments, 0));
                            }
                            eKey = getString(arguments, 1);

                        } else if (numberOfArgs == 2) {
                            if (customTag.getString("argument1Type").equals("String")) {
                                customTagOptions.put("param1", getString(arguments, 0));
                            } else if (customTag.getString("argument1Type").equals("Number")) {
                                customTagOptions.put("param1", getInt(arguments, 0));
                            }
                            if (customTag.getString("argument2Type").equals("String")) {
                                customTagOptions.put("param2", getString(arguments, 1));
                            } else if (customTag.getString("argument2Type").equals("Number")) {
                                customTagOptions.put("param2", getInt(arguments, 1));
                            }
                            eKey = getString(arguments, 2);
                        } else {
                            eKey = getString(arguments, 0);
                        }

                        if (customTagName.equals(tag)) {
                            String language = customTag.getString("language").toLowerCase();
                            String code = customTag.getString("code");
                            if (language.equals("javascript")) {
                                output = javascript(variableMap, output, code, eKey, customTagOptions);
                            } else {
                                output = python(variableMap, output, code, eKey, customTagOptions);
                            }
                            break;
                        }
                    }
                } else {
                    output = charset_convert(output, "UTF-8", tag);
                }
                break;
            case "charset_convert":
                output = charset_convert(output, getString(arguments, 0), getString(arguments, 1));
                break;
            case "utf7":
                output = utf7(output, getString(arguments, 0));
                break;
            case "brotli_decompress":
                output = brotli_decompress(output);
                break;
            case "gzip_compress":
                output = gzip_compress(output);
                break;
            case "gzip_decompress":
                output = gzip_decompress(output);
                break;
            case "bzip2_compress":
                output = bzip2_compress(output);
                break;
            case "bzip2_decompress":
                output = bzip2_decompress(output);
                break;
            case "deflate_compress":
                output = deflate_compress(output);
                break;
            case "deflate_decompress":
                output = deflate_decompress(output);
                break;
            case "timestamp":
                output = timestamp();
                break;
            case "date":
                output = date(getString(arguments, 0));
                break;
            case "html_entities":
                output = html_entities(output);
                break;
            case "d_html_entities":
                output = decode_html_entities(output);
                break;
            case "html5_entities":
                output = html5_entities(output);
                break;
            case "hex":
                output = hex(output, getString(arguments, 0));
                break;
            case "hex_entities":
                output = hex_entities(output);
                break;
            case "hex_escapes":
                output = hex_escapes(output);
                break;
            case "octal_escapes":
                output = octal_escapes(output);
                break;
            case "php_non_alpha":
                output = php_non_alpha(output);
                break;
            case "php_chr":
                output = php_chr(output);
                break;
            case "sql_hex":
                output = sql_hex(output);
                break;
            case "rotN":
                output = rotN(output, getInt(arguments, 0));
                break;
            case "aes_encrypt":
                output = aes_encrypt(output, getString(arguments, 0), getString(arguments, 1), getString(arguments, 2));
                break;
            case "aes_decrypt":
                output = aes_decrypt(output, getString(arguments, 0), getString(arguments, 1), getString(arguments, 2));
                break;
            case "rotN_bruteforce":
                output = rotN_bruteforce(output);
                break;
            case "xor":
                output = xor(output, getString(arguments, 0));
                break;
            case "xor_decrypt":
                output = xor_decrypt(output, getInt(arguments, 0), false);
                break;
            case "xor_getkey":
                output = xor_getkey(output);
                break;
            case "affine_encrypt":
                output = affine_encrypt(output, getInt(arguments, 0), getInt(arguments, 1));
                break;
            case "affine_decrypt":
                output = affine_decrypt(output, getInt(arguments, 0), getInt(arguments, 1));
                break;
            case "atbash_encrypt":
                output = atbash_encrypt(output);
                break;
            case "atbash_decrypt":
                output = atbash_decrypt(output);
                break;
            case "rail_fence_encrypt":
                output = rail_fence_encrypt(output, getInt(arguments, 0));
                break;
            case "rail_fence_decrypt":
                output = rail_fence_decrypt(output, getInt(arguments, 0));
                break;
            case "substitution_encrypt":
                output = substitution_encrypt(output, getString(arguments, 0));
                break;
            case "substitution_decrypt":
                output = substitution_decrypt(output, getString(arguments, 0));
                break;
            case "jwt":
                output = jwt(output, getString(arguments, 0), getString(arguments, 1));
                break;
            case "auto_decode":
                output = auto_decode(output);
                break;
            case "auto_decode_no_decrypt":
                output = auto_decode_no_decrypt(output);
                break;
            case "d_octal_escapes":
                output = decode_octal_escapes(output);
                break;
            case "css_escapes":
                output = css_escapes(output);
                break;
            case "css_escapes6":
                output = css_escapes6(output);
                break;
            case "dec_entities":
                output = dec_entities(output);
                break;
            case "unicode_escapes":
                output = unicode_escapes(output);
                break;
            case "d_unicode_escapes":
                output = decode_js_string(output);
                break;
            case "d_jwt_get_payload":
                output = d_jwt_get_payload(output);
                break;
            case "d_jwt_get_header":
                output = d_jwt_get_header(output);
                break;
            case "d_jwt_verify":
                output = d_jwt_verify(output, getString(arguments, 0));
                break;
            case "d_js_string":
                output = decode_js_string(output);
                break;
            case "d_html5_entities":
                output = decode_html5_entities(output);
                break;
            case "base32":
                output = base32_encode(output);
                break;
            case "d_base32":
                output = decode_base32(output);
                break;
            case "base64":
                output = base64Encode(output);
                break;
            case "d_base64":
                output = decode_base64(output);
                break;
            case "base64url":
                output = base64urlEncode(output);
                break;
            case "d_base64url":
                output = decode_base64url(output);
                break;
            case "burp_urlencode":
                output = burp_urlencode(output);
                break;
            case "urlencode":
                output = urlencode(output);
                break;
            case "urlencode_not_plus":
                output = urlencode_not_plus(output);
                break;
            case "urlencode_all":
                output = urlencode_all(output);
                break;
            case "d_burp_url":
                output = burp_decode_url(output);
                break;
            case "d_url":
                output = decode_url(output);
                break;
            case "d_css_escapes":
                output = decode_css_escapes(output);
                break;
            case "uppercase":
                output = uppercase(output);
                break;
            case "lowercase":
                output = lowercase(output);
                break;
            case "unique":
                output = unique(output);
                break;
            case "capitalise":
                output = capitalise(output);
                break;
            case "uncapitalise":
                output = uncapitalise(output);
                break;
            case "from_charcode":
                output = from_charcode(output);
                break;
            case "to_charcode":
                output = to_charcode(output);
                break;
            case "reverse":
                output = reverse(output);
                break;
            case "length":
                output = len(output);
                break;
            case "find":
                output = find(output, getString(arguments, 0));
                break;
            case "replace":
                output = replace(output, getString(arguments, 0), getString(arguments, 1));
                break;
            case "regex_replace":
                output = regex_replace(output, getString(arguments, 0), getString(arguments, 1));
                break;
            case "repeat":
                output = repeat(output, getInt(arguments, 0));
                break;
            case "split_join":
                output = split_join(output, getString(arguments, 0), getString(arguments, 1));
                break;
            case "is_like_english":
                output = Double.toString(is_like_english(output));
                break;
            case "index_of_coincidence":
                output = Double.toString(index_of_coincidence(output));
                break;
            case "guess_key_length":
                output = Integer.toString(guess_key_length(output));
                break;
            case "chunked_dec2hex":
                output = chunked_dec2hex(output);
                break;
            case "dec2hex":
                output = dec2hex(output, getString(arguments, 0));
                break;
            case "dec2oct":
                output = dec2oct(output, getString(arguments, 0));
                break;
            case "dec2bin":
                output = dec2bin(output, getString(arguments, 0));
                break;
            case "hex2dec":
                output = hex2dec(output, getString(arguments, 0));
                break;
            case "oct2dec":
                output = oct2dec(output, getString(arguments, 0));
                break;
            case "bin2dec":
                output = bin2dec(output, getString(arguments, 0));
                break;
            case "ascii2bin":
                output = ascii2bin(output);
                break;
            case "bin2ascii":
                output = bin2ascii(output);
                break;
            case "hex2ascii":
                output = hex2ascii(output);
                break;
            case "ascii2hex":
                output = ascii2hex(output, getString(arguments, 0));
                break;
            case "ascii2reverse_hex":
                output = ascii2reverse_hex(output, getString(arguments, 0));
                break;
            case "hmac_md5":
                output = hmacmd5(output, getString(arguments, 0));
                break;
            case "hmac_sha1":
                output = hmacsha1(output, getString(arguments, 0));
                break;
            case "hmac_sha224":
                output = hmacsha224(output, getString(arguments, 0));
                break;
            case "hmac_sha256":
                output = hmacsha256(output, getString(arguments, 0));
                break;
            case "hmac_sha384":
                output = hmacsha384(output, getString(arguments, 0));
                break;
            case "hmac_sha512":
                output = hmacsha512(output, getString(arguments, 0));
                break;
            case "sha1":
                output = sha1(output);
                break;
            case "sha224":
                output = sha224(output);
                break;
            case "sha256":
                output = sha256(output);
                break;
            case "sha384":
                output = sha384(output);
                break;
            case "sha512":
                output = sha512(output);
                break;
            case "sha3":
                output = sha3(output);
                break;
            case "sha3_224":
                output = sha3_224(output);
                break;
            case "sha3_256":
                output = sha3_256(output);
                break;
            case "sha3_384":
                output = sha3_384(output);
                break;
            case "sha3_512":
                output = sha3_512(output);
                break;
            case "skein_256_128":
                output = skein_256_128(output);
                break;
            case "skein_256_160":
                output = skein_256_160(output);
                break;
            case "skein_256_224":
                output = skein_256_224(output);
                break;
            case "skein_256_256":
                output = skein_256_256(output);
                break;
            case "skein_512_128":
                output = skein_512_128(output);
                break;
            case "skein_512_160":
                output = skein_512_160(output);
                break;
            case "skein_512_224":
                output = skein_512_224(output);
                break;
            case "skein_512_256":
                output = skein_512_256(output);
                break;
            case "skein_512_384":
                output = skein_512_384(output);
                break;
            case "skein_512_512":
                output = skein_512_512(output);
                break;
            case "skein_1024_384":
                output = skein_1024_384(output);
                break;
            case "skein_1024_512":
                output = skein_1024_512(output);
                break;
            case "skein_1024_1024":
                output = skein_1024_1024(output);
                break;
            case "sm3":
                output = sm3(output);
                break;
            case "tiger":
                output = tiger(output);
                break;
            case "md2":
                output = md2(output);
                break;
            case "md4":
                output = md4(output);
                break;
            case "md5":
                output = md5(output);
                break;
            case "gost3411":
                output = gost3411(output);
                break;
            case "ripemd128":
                output = ripemd128(output);
                break;
            case "ripemd160":
                output = ripemd160(output);
                break;
            case "ripemd256":
                output = ripemd256(output);
                break;
            case "ripemd320":
                output = ripemd320(output);
                break;
            case "whirlpool":
                output = whirlpool(output);
                break;
            case "random":
                output = random(output, getInt(arguments, 0));
                break;
            case "random_num":
                output = random_num(getInt(arguments, 0));
                break;
            case "random_unicode":
                output = random_unicode(getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
                break;
            case "range":
                output = range(output, getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
                break;
            case "total":
                output = total(output);
                break;
            case "arithmetic":
                output = arithmetic(output, getInt(arguments, 0), getString(arguments, 1), getString(arguments, 2));
                break;
            case "convert_base":
                output = convert_base(output, getString(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
                break;
            case "zeropad":
                output = zeropad(output, getString(arguments, 0), getInt(arguments, 1));
                break;
            case "behavior":
                output = behavior(output);
                break;
            case "css_expression":
                output = css_expression(output);
                break;
            case "datasrc":
                output = datasrc(output);
                break;
            case "eval_fromcharcode":
                output = eval_fromcharcode(output);
                break;
            case "iframe_data_url":
                output = iframe_data_url(output);
                break;
            case "script_data":
                output = script_data(output);
                break;
            case "uppercase_script":
                output = uppercase_script(output);
                break;
            case "iframe_src_doc":
                output = iframe_src_doc(output);
                break;
            case "template_eval":
                output = template_eval(output);
                break;
            case "throw_eval":
                output = throw_eval(output);
                break;
            case "python":
                output = python(variableMap, output, getString(arguments, 0), getString(arguments, 1), null);
                break;
            case "javascript":
                output = javascript(variableMap, output, getString(arguments, 0), getString(arguments, 1), null);
                break;
            case "loop_for":
                output = loop_for(variableMap, customTags, output, getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2), getString(arguments, 3));
                break;
            case "loop_letters_lower":
                output = loop_letters_lower(variableMap, customTags, output, getString(arguments, 0));
                break;
            case "loop_letters_upper":
                output = loop_letters_upper(variableMap, customTags, output, getString(arguments, 0));
                break;
            case "loop_numbers":
                output = loop_letters_numbers(variableMap, customTags, output, getString(arguments, 0));
                break;
        }
        return output;
    }

    public static String convertNoInputTags(HashMap<String, String> variableMap, JSONArray customTags, String input) {
        java.util.List<String> allMatches = new ArrayList<>();
        Matcher m = Pattern.compile("<@([\\w\\d\\-]+(_\\d*)?)((?:[(](?:,?" + argumentsRegex + ")*[)])?) />").matcher(input);
        while (m.find()) {
            allMatches.add(m.group(1));
        }
        for (String tagNameWithID : allMatches) {
            String arguments = "";
            String tagName = tagNameWithID.replaceAll("_\\d+$", "");
            m = Pattern.compile("<@" + tagNameWithID + "((?:[(](?:,?" + argumentsRegex + ")*[)])?) />").matcher(input);
            if (m.find()) {
                arguments = m.group(1);
            }
            String result;
            if (tagName.startsWith("get_")) {
                result = variableMap.getOrDefault(tagName,"");
            } else {
                result = callTag(variableMap, customTags, tagName, "", parseArguments(arguments));
            }
            input = input.replaceAll("<@" + tagNameWithID + "(?:[(](?:,?" + argumentsRegex + ")*[)])? />", result.replace("\\", "\\\\").replace("$", "\\$"));
        }
        return input;
    }

    public static String[] generateTagStartEnd(Tag tagObj) {
        String tagStart;
        String tagEnd;
        int tagNo = (new Random().nextInt(10000));
        tagStart = "<@" + tagObj.name + "_" + tagNo;
        if (tagObj.argument1 != null) {
            tagStart += "(";
        }
        if (tagObj.argument1 != null) {
            if (tagObj.argument1.type.equals("int")) {
                tagStart += tagObj.argument1.value;
            } else if (tagObj.argument1.type.equals("string")) {
                tagStart += "\"" + tagObj.argument1.value + "\"";
            }
        }
        if (tagObj.argument2 != null) {
            tagStart += ",";
            if (tagObj.argument2.type.equals("int")) {
                tagStart += tagObj.argument2.value;
            } else if (tagObj.argument2.type.equals("string")) {
                tagStart += "\"" + tagObj.argument2.value + "\"";
            }
        }
        if (tagObj.argument3 != null) {
            tagStart += ",";
            if (tagObj.argument3.type.equals("int")) {
                tagStart += tagObj.argument3.value;
            } else if (tagObj.argument3.type.equals("string")) {
                tagStart += "\"" + tagObj.argument3.value + "\"";
            }
        }
        if (tagObj.argument4 != null) {
            tagStart += ",";
            if (tagObj.argument4.type.equals("int")) {
                tagStart += tagObj.argument4.value;
            } else if (tagObj.argument4.type.equals("string")) {
                tagStart += "\"" + tagObj.argument4.value + "\"";
            }
        }
        if (tagObj.argument1 != null) {
            tagStart += ")";
        }
        if (tagObj.hasInput) {
            tagStart += ">";
            tagEnd = "<@/" + tagObj.name + "_" + tagNo + ">";
        } else {
            tagStart += " />";
            tagEnd = "";
        }
        return new String[]{tagStart, tagEnd};
    }

    public static ArrayList<String> parseArguments(String arguments) {
        if (arguments.length() == 0) {
            return new ArrayList<>();
        }
        arguments = arguments.substring(1, arguments.length() - 1);
        String argument1;
        String argument2;
        String argument3;
        String argument4;
        ArrayList<String> convertedArgs = new ArrayList<>();
        String regex = "(" + argumentsRegex + ")(," + argumentsRegex + ")?(," + argumentsRegex + ")?(," + argumentsRegex + ")?";
        Matcher m = Pattern.compile(regex).matcher(arguments);
        if (m.find()) {
            argument1 = m.group(1);
            argument2 = m.group(2);
            argument3 = m.group(3);
            argument4 = m.group(4);
            if (argument1 != null) {
                String chr = "" + argument1.charAt(0);
                if (chr.equals("'") || chr.equals("\"")) {
                    argument1 = argument1.substring(1, argument1.length() - 1);
                    argument1 = argument1.replace("\\'", "'").replace("\\\"", "\"");
                    convertedArgs.add(decode_js_string(argument1));
                } else {
                    convertedArgs.add(argument1);
                }
            }
            if (argument2 != null) {
                argument2 = argument2.substring(1);
                String chr = "" + argument2.charAt(0);
                if (chr.equals("'") || chr.equals("\"")) {
                    argument2 = argument2.substring(1, argument2.length() - 1);
                    argument2 = argument2.replace("\\'", "'").replace("\\\"", "\"");
                    convertedArgs.add(decode_js_string(argument2));
                } else {
                    convertedArgs.add(argument2);
                }
            }
            if (argument3 != null) {
                argument3 = argument3.substring(1);
                String chr = "" + argument3.charAt(0);
                if (chr.equals("'") || chr.equals("\"")) {
                    argument3 = argument3.substring(1, argument3.length() - 1);
                    argument3 = argument3.replace("\\'", "'").replace("\\\"", "\"");
                    convertedArgs.add(decode_js_string(argument3));
                } else {
                    convertedArgs.add(argument3);
                }
            }
            if (argument4 != null) {
                argument4 = argument4.substring(1);
                String chr = "" + argument4.charAt(0);
                if (chr.equals("'") || chr.equals("\"")) {
                    argument4 = argument4.substring(1, argument4.length() - 1);
                    argument4 = argument4.replace("\\'", "'").replace("\\\"", "\"");
                    convertedArgs.add(decode_js_string(argument4));
                } else {
                    convertedArgs.add(argument4);
                }
            }
        }
        return convertedArgs;
    }

    public static String convert(JSONArray customTags, String input){
        return convert(new HashMap<>(), customTags, input);
    }

    private static String convert(HashMap<String, String> variableMap, JSONArray customTags, String input) {
        if (input.contains("<@loop_")) {
            input = convertLoops(variableMap, customTags, input);
        }
        if (input.contains("<@set_")) {
            input = convertSetVariables(variableMap, customTags, input);
        }
        if (input.contains(" />")) {
            input = convertNoInputTags(variableMap, customTags, input);
        }
        String output = input;
        List<String> allMatches = new ArrayList<>();
        Matcher m = Pattern.compile("<@/([\\w\\d\\-]+(?:_\\d+)?)>").matcher(input);
        while (m.find()) {
            allMatches.add(m.group(1));
        }
        for (String tagNameWithID : allMatches) {
            String code = "";
            String arguments = "";
            String tagName = tagNameWithID.replaceAll("_\\d+$", "");
            m = Pattern.compile("<@" + tagNameWithID + "((?:[(](?:,?" + argumentsRegex + ")*[)])?)>([\\d\\D]*?)<@/" + tagNameWithID + ">").matcher(output);
            if (m.find()) {
                arguments = m.group(1);
                code = m.group(2);
            }
            String result = callTag(variableMap, customTags, tagName, code, parseArguments(arguments));
            output = output.replaceAll("<@" + tagNameWithID + "(?:[(](?:,?" + argumentsRegex + ")*[)])?>[\\d\\D]*?<@/" + tagNameWithID + ">", result.replace("\\", "\\\\").replace("$", "\\$"));
        }
        return output;
    }

    public static String convertSetVariables(HashMap<String, String> variableMap, JSONArray customTags, String input) {
        String output = input;
        java.util.List<String> allMatches = new ArrayList<>();
        Matcher m = Pattern.compile("<@(set_[\\w\\d\\-]+(?:_\\d+)?)>").matcher(input);
        while (m.find()) {
            allMatches.add(m.group(1));
        }
        for (String tagNameWithID : allMatches) {
            String code = "";
            String tagName = tagNameWithID.replaceAll("_\\d+$", "");
            m = Pattern.compile("<@" + tagNameWithID + ">([\\d\\D]*?)<@/" + tagNameWithID + ">").matcher(output);
            if (m.find()) {
                code = m.group(1);
            }
            variableMap.put(tagName, convert(variableMap, customTags, code));
            String result = code.replaceAll("<@/?[\\w\\-]+(?:_\\d+)?(?:[(](?:,?" + argumentsRegex + ")*[)])?(?:\\s/)?>", "");
            output = output.replaceAll("<@" + tagNameWithID + "(?:[(](?:,?" + argumentsRegex + ")*[)])?>[\\d\\D]*?<@/" + tagNameWithID + ">", result.replace("\\", "\\\\").replace("$", "\\$"));
        }
        return output;
    }

    public static String convertLoops(HashMap<String, String> variableMap, JSONArray customTags, String input) {
        String output = input;
        java.util.List<String> allMatches = new ArrayList<>();
        Matcher m = Pattern.compile("<@(loop_[\\w\\d\\-]+(?:_\\d+)?)((?:[(](?:,?" + argumentsRegex + ")*[)])?)>").matcher(input);
        while (m.find()) {
            allMatches.add(m.group(1));
        }
        for (String tagNameWithID : allMatches) {
            String arguments = "";
            String code = "";
            String tagName = tagNameWithID.replaceAll("_\\d+$", "");
            m = Pattern.compile("<@" + tagNameWithID + "((?:[(](?:,?" + argumentsRegex + ")*[)])?)>([\\d\\D]*?)<@/" + tagNameWithID + ">").matcher(output);
            if (m.find()) {
                arguments = m.group(1);
                code = m.group(2);
            }
            String result = callTag(variableMap, customTags, tagName, code, parseArguments(arguments));
            output = output.replaceAll("<@" + tagNameWithID + "(?:[(](?:,?" + argumentsRegex + ")*[)])?>[\\d\\D]*?<@/" + tagNameWithID + ">", result.replace("\\", "\\\\").replace("$", "\\$"));
        }
        return output;
    }

    static String convertCharset(String input, String to) {
        String output = "";
        try {
            return helpers.bytesToString(input.getBytes(to));
        } catch (UnsupportedEncodingException e) {
            return e.toString();
        }
    }

    static String charset_convert(String input, String from, String to) {
        byte[] inputBytes = input.getBytes();
        byte[] output = new byte[0];
        try {
            output = new String(inputBytes, from).getBytes(to);
        } catch (UnsupportedEncodingException e) {
            return e.toString();
        }
        return helpers.bytesToString(output);
    }

    static String utf7(String input, String excludeCharacters) {
        String output = "";
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (excludeCharacters.indexOf(c) > -1) {
                output += c;
                continue;
            }
            output += "+" + base64Encode("\u0000" + c).replaceAll("=+$", "") + "-";

        }
        return output;
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

    static String deflate_compress(String input) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
        CompressorOutputStream cos = null;
        try {
            cos = new CompressorStreamFactory()
                    .createCompressorOutputStream(CompressorStreamFactory.getDeflate(), bos);
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

    static String deflate_decompress(String input) {
        ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
        DeflateCompressorInputStream cis = null;
        byte[] bytes;
        try {
            cis = new DeflateCompressorInputStream(bis);
            bytes = IOUtils.toByteArray(cis);
            return new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return "Error:" + e.toString();
        }
    }

    static String timestamp() {
        long unixTime = System.currentTimeMillis() / 1000L;
        return unixTime + "";
    }

    static String date(String format) {
        try {
            SimpleDateFormat dateF = new SimpleDateFormat(format);
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
        return new String(base32.encode(str.getBytes()));
    }

    static String decode_base32(String str) {
        Base32 base32 = new Base32();
        return new String(base32.decode(str.getBytes()));
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
            if (codePoint <= 0xff) {
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
        return random("0123456789", len);
    }

    static String random(String chars, int len) {
        if (len > 0 && chars.length() > 0) {
            StringBuilder sb = new StringBuilder();
            Random random = new Random();
            for (int i = 0; i < len; i++) {
                sb.append(chars.charAt(random.nextInt(chars.length())));
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

    static String unique(String str) {
        String words[] = str.split(" ");
        Set result = new HashSet(Arrays.asList(words));
        return String.join(" ", result);
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
            String header = "{\n" +
                    "  \"alg\": \"" + algo + "\",\n" +
                    "  \"typ\": \"JWT\"\n" +
                    "}";
            message = base64urlEncode(header) + "." + base64urlEncode(payload);
            if (!algoName.equals("none")) {
                Mac hashMac = Mac.getInstance(algoName);
                SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), algoName);
                hashMac.init(secret_key);
                return message + "." + base64urlEncode(helpers.bytesToString(hashMac.doFinal(message.getBytes())));
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
                    .withIssuer(jwt.getIssuer())
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
        message = message.toLowerCase();
        String encoded = "";
        String key = "ZYXWVUTSRQPONMLKJIHGFEDCBA".toLowerCase();
        for (int i = 0; i < message.length(); i++) {
            char chr = message.charAt(i);
            if (Character.isLowerCase(chr)) {
                encoded += key.charAt(message.codePointAt(i) - 97);
            } else {
                encoded += chr;
            }
        }
        return encoded;
    }

    static String atbash_decrypt(String ciphertext) {
        ciphertext = ciphertext.toLowerCase();
        String plaintext = "";
        String key = "ZYXWVUTSRQPONMLKJIHGFEDCBA".toLowerCase();
        for (int i = 0; i < ciphertext.length(); i++) {
            char chr = ciphertext.charAt(i);
            if (Character.isLowerCase(chr)) {
                plaintext += (char) (key.indexOf(ciphertext.charAt(i)) + 97);
            } else {
                plaintext += chr;
            }
        }
        return plaintext;
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

    static String dec2hex(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = zeropad(Integer.toHexString(Integer.parseInt(chars[i])), ",", 2);
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String chunked_dec2hex(String str) {
        try {
            return Integer.toHexString(Integer.parseInt(str));
        } catch (NumberFormatException e) {
            return e.getMessage();
        }
    }

    static String dec2oct(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = Integer.toOctalString(Integer.parseInt(chars[i]));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String dec2bin(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = Integer.toBinaryString(Integer.parseInt(chars[i]));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String hex2dec(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = Integer.toString(Integer.parseInt(chars[i], 16));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String oct2dec(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = Integer.toString(Integer.parseInt(chars[i], 8));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
    }

    static String bin2dec(String str, String splitChar) {
        String[] chars = {};
        try {
            chars = str.split(splitChar);
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        for (int i = 0; i < chars.length; i++) {
            try {
                chars[i] = Integer.toString(Integer.parseInt(chars[i], 2));
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return StringUtils.join(chars, ",");
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
        String output = "";
        String hex = "";
        for (int i = 0; i < str.length(); i++) {
            try {
                hex = Integer.toHexString(Character.codePointAt(str, i));
                if (hex.length() % 2 != 0) {
                    hex = "0" + hex;
                }
                output += hex;
                if (separator.length() > 0 && i < str.length() - 1) {
                    output += separator;
                }
            } catch (NumberFormatException e) {
                stderr.println(e.getMessage());
            }
        }
        return output;
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
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
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

    static String find(String str, String find) {
        java.util.List<String> allMatches = new ArrayList<String>();
        try {
            Matcher m = Pattern.compile(find).matcher(str);
            while (m.find()) {
                allMatches.add(m.group());
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
            output = str.replaceAll(find, replace.replace("\\", "\\\\").replace("$", "\\$"));
        } catch (PatternSyntaxException e) {
            stderr.println(e.getMessage());
        }
        return output;
    }

    static String repeat(String str, int amount) {
        String output = "";
        if (amount > 0 && amount < 10000) {
            for (int i = 0; i < amount; i++) {
                output += str;
            }
        }
        return output;
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

    static String auto_decode(String str) {
        return auto_decode_decrypt(str, true);
    }

    static String auto_decode_no_decrypt(String str) {
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
                encodingOpeningTags = encodingOpeningTags + "<@gzip_compress_" + tagNo + ">";
                encodingClosingTags = "<@/gzip_compress_" + tagNo + ">" + encodingClosingTags;
            }
            if (Pattern.compile("[01]{4,}\\s+[01]{4,}").matcher(str).find()) {
                str = bin2ascii(str);
                matched = true;
                encodingOpeningTags = encodingOpeningTags + "<@ascii2bin_" + tagNo + ">";
                encodingClosingTags = "<@/ascii2bin_" + tagNo + ">" + encodingClosingTags;
            }
            if (Pattern.compile("(?:[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = hex2ascii(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    encodingOpeningTags = encodingOpeningTags + "<@ascii2hex_" + tagNo + "(\" \")>";
                    encodingClosingTags = "<@/ascii2hex_" + tagNo + ">" + encodingClosingTags;
                    repeat++;
                    continue;
                }
            }
            if (Pattern.compile("^[0-9a-fA-F]+$").matcher(str).find() && str.length() % 2 == 0) {
                str = hex2ascii(str);
                matched = true;
                encodingOpeningTags = encodingOpeningTags + "<@ascii2hex_" + tagNo + "(\"\")>";
                encodingClosingTags = "<@/ascii2hex_" + tagNo + ">" + encodingClosingTags;
            }
            if (!Pattern.compile("[^\\d,\\s]").matcher(str).find() && Pattern.compile("\\d+[,\\s]+").matcher(str).find()) {
                str = from_charcode(str);
                matched = true;
                encodingOpeningTags = encodingOpeningTags + "<@to_charcode_" + tagNo + ">";
                encodingClosingTags = "<@/to_charcode_" + tagNo + ">" + encodingClosingTags;
            }
            if (Pattern.compile("(?:\\\\[0]{0,4}[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = decode_css_escapes(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags = encodingOpeningTags + "<@css_escapes_" + tagNo + ">";
                    encodingClosingTags = "<@/css_escapes_" + tagNo + ">" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\x[0-9a-f]{2}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags = encodingOpeningTags + "<@hex_escapes_" + tagNo + ">";
                    encodingClosingTags = "<@/hex_escapes_" + tagNo + ">" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\[0-9]{1,3}").matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags = encodingOpeningTags + "<@octal_escapes_" + tagNo + ">";
                    encodingClosingTags = "<@/octal_escapes_" + tagNo + ">" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\u[0-9a-f]{4}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags = encodingOpeningTags + "<@unicode_escapes_" + tagNo + ">";
                    encodingClosingTags = "<@/unicode_escapes_" + tagNo + ">" + encodingClosingTags;
                }
            }
            if (Pattern.compile("&[a-zA-Z]+;", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags = encodingOpeningTags + "<@html_entities_" + tagNo + ">";
                encodingClosingTags = "<@/html_entities_" + tagNo + ">" + encodingClosingTags;
            }
            if (Pattern.compile("&#x?[0-9a-f]+;?", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags = encodingOpeningTags + "<@hex_entities_" + tagNo + ">";
                encodingClosingTags = "<@/hex_entities_" + tagNo + ">" + encodingClosingTags;
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
                    encodingOpeningTags = encodingOpeningTags + "<@urlencode_" + tagNo + ">";
                    encodingClosingTags = "<@/urlencode_" + tagNo + ">" + encodingClosingTags;
                } else {
                    tag = "urlencode_not_plus";
                    encodingOpeningTags = encodingOpeningTags + "<@urlencode_not_plus_" + tagNo + ">";
                    encodingClosingTags = "<@/urlencode_not_plus_" + tagNo + ">" + encodingClosingTags;
                }
            }
            if (Pattern.compile("^[a-zA-Z0-9\\-_.]+$", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                String[] parts = str.split("\\.");
                if (parts.length == 3 && !d_jwt_get_header(str).equals("Invalid token")) {
                    return d_jwt_get_header(str) + "\n" + d_jwt_get_payload(str) + "\n" + decode_base64url(parts[2]);
                }
            }
            if (Pattern.compile("[a-zA-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0) {
                test = decode_base64(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base64";
                    encodingOpeningTags = encodingOpeningTags + "<@base64_" + tagNo + ">";
                    encodingClosingTags = "<@/base64_" + tagNo + ">" + encodingClosingTags;
                }
            }

            if (Pattern.compile("[A-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0) {
                test = decode_base32(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base32";
                    encodingOpeningTags = encodingOpeningTags + "<@base32_" + tagNo + ">";
                    encodingClosingTags = "<@/base32_" + tagNo + ">" + encodingClosingTags;
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
                        encodingOpeningTags = encodingOpeningTags + "<@rotN_" + tagNo + "(" + n + ")>";
                        encodingClosingTags = "<@/rotN_" + tagNo + ">" + encodingClosingTags;
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
                        encodingOpeningTags = encodingOpeningTags + "<@affine_encrypt_" + tagNo + "(" + key1 + "," + key2 + ")>";
                        encodingClosingTags = "<@/affine_encrypt_" + tagNo + ">" + encodingClosingTags;
                    }
                }

                if (Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
                    String plaintext = atbash_decrypt(str);
                    if (is_like_english(plaintext) - is_like_english(str) >= 200) {
                        str = plaintext;
                        matched = true;
                        tag = "atbash";
                        encodingOpeningTags = encodingOpeningTags + "<@atbash_encrypt_" + tagNo + ">";
                        encodingClosingTags = "<@/atbash_encrypt_" + tagNo + ">" + encodingClosingTags;
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
                        encodingOpeningTags = encodingOpeningTags + "<@rail_fence_encrypt_" + tagNo + "(" + n + ")>";
                        encodingClosingTags = "<@/rail_fence_encrypt_" + tagNo + ">" + encodingClosingTags;
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
                        encodingOpeningTags = encodingOpeningTags + "<@xor_" + tagNo + "(\"" + key + "\")>";
                        encodingClosingTags = "<@/xor_" + tagNo + ">" + encodingClosingTags;
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

    static String python(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions) {
        if (!codeExecutionTagsEnabled) {
            return "Code execution tags are disabled by default. Use the menu bar to enable them.";
        }
        if (executionKey == null) {
            return "No execution key defined";
        }
        if (executionKey.length() != 32) {
            return "Code execution key length incorrect";
        }
        if (!tagCodeExecutionKey.equals(executionKey)) {
            return "Incorrect tag code execution key";
        }
        try {
            PythonInterpreter pythonInterpreter = new PythonInterpreter();
            pythonInterpreter.set("input", input);
            for (Map.Entry<String, String> entry : variableMap.entrySet()) {
                String name = entry.getKey();
                Object value = entry.getValue();
                if (name.length() > 0) {
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
                pythonInterpreter.exec(code);
            }
            PyObject output = pythonInterpreter.get("output");
            if (output != null) {
                return output.asString();
            } else {
                return "No output variable defined";
            }
        } catch (PyException e) {
            return "Invalid Python code:" + e.toString();
        } catch (Exception e) {
            return "Unable to parse Python:" + e.toString();
        }
    }

    static String javascript(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions) {
        if (!codeExecutionTagsEnabled) {
            return "Code execution tags are disabled by default. Use the menu bar to enable them.";
        }
        if (executionKey == null) {
            return "No execution key defined";
        }
        if (executionKey.length() != 32) {
            return "Code execution key length incorrect";
        }
        if (!tagCodeExecutionKey.equals(executionKey)) {
            return "Incorrect tag code execution key";
        }
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        engine.put("input", input);
        for (Map.Entry<String, String> entry : variableMap.entrySet()) {
            String name = entry.getKey();
            Object value = entry.getValue();
            if (name.length() > 0) {
                engine.put(name, value);
            }
        }
        if (customTagOptions != null) {
            JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
            int numberOfArgs = customTag.getInt("numberOfArgs");
            if (numberOfArgs == 1) {
                engine.put(customTag.getString("argument1"), customTagOptions.get("param1"));
            }
            if (numberOfArgs == 2) {
                engine.put(customTag.getString("argument1"), customTagOptions.get("param1"));
                engine.put(customTag.getString("argument2"), customTagOptions.get("param2"));
            }
        }
        try {
            if (code.endsWith(".js")) {
                engine.eval(new FileReader(code));
            } else {
                engine.eval(code);
            }
            return engine.get("output").toString();
        } catch (ScriptException e) {
            return "Invalid JavaScript:" + e.toString();
        } catch (FileNotFoundException e) {
            return "Unable to find JavaScript file:" + e.toString();
        } catch (NullPointerException e) {
            return "Unable to get output. Make sure you have defined an output variable:" + e.toString();
        } catch (IllegalArgumentException e) {
            return "Invalid JavaScript:" + e.toString();
        } catch (AssertionError e) {
            return "Unable to parse JavaScript:" + e.toString();
        } catch (Exception e) {
            return "Unable to parse JavaScript:" + e.toString();
        }
    }

    static String loop_for(HashMap<String, String> variableMap, JSONArray customTags, String input, int start, int end, int increment, String variable) {
        String output = "";
        for (int i = start; i < end; i += increment) {
            variableMap.put(variable, Integer.toString(i));
            output += convert(variableMap, customTags, input);
        }
        return output;
    }

    static String loop_letters_lower(HashMap<String, String> variableMap, JSONArray customTags, String input, String variable) {
        String output = "";
        for (char letter = 'a'; letter <= 'z'; letter++) {
            variableMap.put(variable, Character.toString(letter));
            output += convert(variableMap, customTags, input);
        }
        return output;
    }

    static String loop_letters_upper(HashMap<String, String> variableMap, JSONArray customTags, String input, String variable) {
        String output = "";
        for (char letter = 'A'; letter <= 'Z'; letter++) {
            variableMap.put(variable, Character.toString(letter));
            output += convert(variableMap, customTags, input);
        }
        return output;
    }

    static String loop_letters_numbers(HashMap<String, String> variableMap, JSONArray customTags, String input, String variable) {
        String output = "";
        for (char num = '0'; num <= '9'; num++) {
            variableMap.put(variable, Character.toString(num));
            output += convert(variableMap, customTags, input);
        }
        return output;
    }
}
