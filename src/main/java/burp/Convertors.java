package burp;

import bsh.EvalError;
import bsh.Interpreter;
import burp.parser.Element;
import burp.parser.HackvertorParser;
import burp.parser.ParseException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.eclipsesource.v8.*;
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
import org.apache.commons.compress.compressors.deflate.DeflateParameters;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.util.encoders.Hex;
import org.brotli.dec.BrotliInputStream;
import org.codehaus.groovy.control.CompilationFailedException;
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
import org.unbescape.json.JsonEscape;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.*;

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

    public static Boolean getBoolean(ArrayList<String> args, Integer pos) {
        if (args.size() < pos + 1) {
            return false;
        }
        return Boolean.valueOf(args.get(pos));
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

    public static String callTag(HashMap<String, String> variableMap, JSONArray customTags, String tag, String output, ArrayList<String> arguments, Hackvertor hackvertor) throws ParseException {
        if(allowTagCount) {
            int count = tagCount.get(tag) == null ? 0 : tagCount.get(tag);
            tagCount.put(tag, count + 1);
        }
        for(int i=0;i<arguments.size();i++) {
            arguments.set(i, convert(variableMap, customTags, arguments.get(i)));
        }

        switch (tag) {
            default:
                if (tag.startsWith("fake_")) {
                    return fake(tag, getString(arguments, 0), getString(arguments, 1));
                } else if (tag.startsWith("_")) {
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
                                return javascript(variableMap, output, code, eKey, customTagOptions, customTags);
                            } else if (language.equals("python")) {
                                return python(variableMap, output, code, eKey, customTagOptions, customTags);
                            } else if (language.equals("java")) {
                                return java(variableMap, output, code, eKey, customTagOptions, customTags);
                            } else if (language.equals("groovy")) {
                                return groovy(variableMap, output, code, eKey, customTagOptions, customTags);
                            }
                        }
                    }
                }else if(tag.startsWith("set_")){ //Backwards compatibility with previous set_VARNAME tag format
                    String varname = tag.replace("set_","");
                    variableMap.put(varname, output);
                    Boolean global = getBoolean(arguments, 0);
                    if(global) {
                        globalVariables.put(varname, output);
                    }
                    return output;
                }else if(tag.startsWith("get_")){ //Backwards compatibility with previous get_VARNAME tag format
                    String varname = tag.replace("get_","");
                    if(globalVariables.containsKey(varname) && !variableMap.containsKey(varname)) {
                        return globalVariables.getOrDefault(varname, StringUtils.isEmpty(output) ? null : output);
                    }
                    return variableMap.getOrDefault(varname, StringUtils.isEmpty(output) ? null : output);
                } else {
                    try {
                        return charset_convert(output, "UTF-8", tag);
                    } catch (UnsupportedEncodingException e) {
                        //Not a valid tag. Check for old-style tag with _0 style ids.
                        if(tag.matches(".*_\\d+$")) {
                            String tagWithoutID = tag.replaceFirst("_\\d+$", "");
                            try {
                                return callTag(variableMap, customTags, tagWithoutID, output, arguments, null);
                            } catch (ParseException e1) { }
                        }

                        throw new ParseException("Unsupported Tag \"" + tag + "\"");
                    }
                }
                return output;
            case "set":
            case "set_var":
            case "set_variable":
                variableMap.put(getString(arguments, 0), output);
                return output;
            case "get":
            case "get_var":
            case "get_variable":
                return variableMap.getOrDefault(getString(arguments,0), StringUtils.isEmpty(output) ? "UNDEFINED" : output);
            case "context_url":
                return context_url(getString(arguments,0), hackvertor);
            case "context_header":
                return context_header(getString(arguments,0), hackvertor);
            case "context_body":
                return context_body(hackvertor);
            case "context_param":
                return context_param(getString(arguments,0), hackvertor);
            case "charset_convert": {
                try {
                    return charset_convert(output, getString(arguments, 0), getString(arguments, 1));
                } catch (UnsupportedEncodingException e) {
                    throw new ParseException("Unsupported encoding \"" + e.getCause().getMessage() + "\"");
                }
            }
            case "utf7":
                return utf7(output, getString(arguments, 0));
            case "brotli_decompress":
                return brotli_decompress(output);
            case "gzip_compress":
                return gzip_compress(output);
            case "gzip_decompress":
                return gzip_decompress(output);
            case "bzip2_compress":
                return bzip2_compress(output);
            case "bzip2_decompress":
                return bzip2_decompress(output);
            case "d_saml":
                return d_saml(output);
            case "deflate_compress":
                return deflate_compress(output);
            case "deflate_decompress":
                return deflate_decompress(output, getBoolean(arguments, 0));
            case "timestamp":
                return timestamp();
            case "date":
                return date(getString(arguments, 0), getString(arguments, 1));
            case "html_entities":
                return html_entities(output);
            case "d_html_entities":
                return decode_html_entities(output);
            case "html5_entities":
                return html5_entities(output);
            case "hex":
                return hex(output, getString(arguments, 0));
            case "hex_entities":
                return hex_entities(output);
            case "hex_escapes":
                return hex_escapes(output);
            case "octal_escapes":
                return octal_escapes(output);
            case "php_non_alpha":
                return php_non_alpha(output);
            case "php_chr":
                return php_chr(output);
            case "sql_hex":
                return sql_hex(output);
            case "rotN":
                return rotN(output, getInt(arguments, 0));
            case "aes_encrypt":
                return aes_encrypt(output, getString(arguments, 0), getString(arguments, 1), getString(arguments, 2));
            case "aes_decrypt":
                return aes_decrypt(output, getString(arguments, 0), getString(arguments, 1), getString(arguments, 2));
            case "rotN_bruteforce":
                return rotN_bruteforce(output);
            case "xor":
                return xor(output, getString(arguments, 0));
            case "xor_decrypt":
                return xor_decrypt(output, getInt(arguments, 0), false);
            case "xor_getkey":
                return xor_getkey(output);
            case "affine_encrypt":
                return affine_encrypt(output, getInt(arguments, 0), getInt(arguments, 1));
            case "affine_decrypt":
                return affine_decrypt(output, getInt(arguments, 0), getInt(arguments, 1));
            case "atbash_encrypt":
                return atbash_encrypt(output);
            case "atbash_decrypt":
                return atbash_decrypt(output);
            case "rail_fence_encrypt":
                return rail_fence_encrypt(output, getInt(arguments, 0));
            case "rail_fence_decrypt":
                return rail_fence_decrypt(output, getInt(arguments, 0));
            case "substitution_encrypt":
                return substitution_encrypt(output, getString(arguments, 0));
            case "substitution_decrypt":
                return substitution_decrypt(output, getString(arguments, 0));
            case "jwt":
                return jwt(output, getString(arguments, 0), getString(arguments, 1));
            case "quoted_printable":
                return quoted_printable(output);
            case "powershell":
                return powershell(output);
            case "js_string":
                return js_string(output);
            case "d_quoted_printable":
                return d_quoted_printable(output);
            case "auto_decode":
                return auto_decode(output);
            case "auto_decode_no_decrypt":
                return auto_decode_no_decrypt(output);
            case "d_octal_escapes":
                return decode_octal_escapes(output);
            case "css_escapes":
                return css_escapes(output);
            case "css_escapes6":
                return css_escapes6(output);
            case "dec_entities":
                return dec_entities(output);
            case "unicode_escapes":
                return unicode_escapes(output);
            case "d_unicode_escapes":
                return decode_js_string(output);
            case "d_jwt_get_payload":
                return d_jwt_get_payload(output);
            case "d_jwt_get_header":
                return d_jwt_get_header(output);
            case "d_jwt_verify":
                return d_jwt_verify(output, getString(arguments, 0));
            case "d_js_string":
                return decode_js_string(output);
            case "d_html5_entities":
                return decode_html5_entities(output);
            case "base32":
                return base32_encode(output);
            case "d_base32":
                return decode_base32(output);
            case "base64":
                return base64Encode(output);
            case "d_base64":
                return decode_base64(output);
            case "base64url":
                return base64urlEncode(output);
            case "d_base64url":
                return decode_base64url(output);
            case "json_parse":
                return json_parse(output, getString(arguments, 0));
            case "burp_urlencode":
                return burp_urlencode(output);
            case "urlencode":
                return urlencode(output);
            case "urlencode_not_plus":
                return urlencode_not_plus(output);
            case "urlencode_all":
                return urlencode_all(output);
            case "d_burp_url":
                return burp_decode_url(output);
            case "d_url":
                return decode_url(output);
            case "d_css_escapes":
                return decode_css_escapes(output);
            case "uppercase":
                return uppercase(output);
            case "lowercase":
                return lowercase(output);
            case "unique":
                return unique(output);
            case "capitalise":
                return capitalise(output);
            case "uncapitalise":
                return uncapitalise(output);
            case "from_charcode":
                return from_charcode(output);
            case "to_charcode":
                return to_charcode(output);
            case "reverse":
                return reverse(output);
            case "length":
                return len(output);
            case "find":
                return find(output, getString(arguments, 0));
            case "replace":
                return replace(output, getString(arguments, 0), getString(arguments, 1));
            case "regex_replace":
                return regex_replace(output, getString(arguments, 0), getString(arguments, 1));
            case "repeat":
                return repeat(output, getInt(arguments, 0));
            case "substring":
                return substring(output, getInt(arguments, 0), getInt(arguments, 1));
            case "split_join":
                return split_join(output, getString(arguments, 0), getString(arguments, 1));
            case "is_like_english":
                return Double.toString(is_like_english(output));
            case "index_of_coincidence":
                return Double.toString(index_of_coincidence(output));
            case "guess_key_length":
                return Integer.toString(guess_key_length(output));
            case "chunked_dec2hex":
                return chunked_dec2hex(output);
            case "dec2hex":
                return dec2hex(output, getString(arguments, 0));
            case "dec2oct":
                return dec2oct(output, getString(arguments, 0));
            case "dec2bin":
                return dec2bin(output, getString(arguments, 0));
            case "hex2dec":
                return hex2dec(output, getString(arguments, 0));
            case "oct2dec":
                return oct2dec(output, getString(arguments, 0));
            case "bin2dec":
                return bin2dec(output, getString(arguments, 0));
            case "ascii2bin":
                return ascii2bin(output);
            case "bin2ascii":
                return bin2ascii(output);
            case "hex2ascii":
                return hex2ascii(output);
            case "ascii2hex":
                return ascii2hex(output, getString(arguments, 0));
            case "ascii2reverse_hex":
                return ascii2reverse_hex(output, getString(arguments, 0));
            case "hmac_md5":
                return hmacmd5(output, getString(arguments, 0));
            case "hmac_sha1":
                return hmacsha1(output, getString(arguments, 0));
            case "hmac_sha224":
                return hmacsha224(output, getString(arguments, 0));
            case "hmac_sha256":
                return hmacsha256(output, getString(arguments, 0));
            case "hmac_sha384":
                return hmacsha384(output, getString(arguments, 0));
            case "hmac_sha512":
                return hmacsha512(output, getString(arguments, 0));
            case "sha1":
                return sha1(output);
            case "sha224":
                return sha224(output);
            case "sha256":
                return sha256(output);
            case "sha384":
                return sha384(output);
            case "sha512":
                return sha512(output);
            case "sha3":
                return sha3(output);
            case "sha3_224":
                return sha3_224(output);
            case "sha3_256":
                return sha3_256(output);
            case "sha3_384":
                return sha3_384(output);
            case "sha3_512":
                return sha3_512(output);
            case "skein_256_128":
                return skein_256_128(output);
            case "skein_256_160":
                return skein_256_160(output);
            case "skein_256_224":
                return skein_256_224(output);
            case "skein_256_256":
                return skein_256_256(output);
            case "skein_512_128":
                return skein_512_128(output);
            case "skein_512_160":
                return skein_512_160(output);
            case "skein_512_224":
                return skein_512_224(output);
            case "skein_512_256":
                return skein_512_256(output);
            case "skein_512_384":
                return skein_512_384(output);
            case "skein_512_512":
                return skein_512_512(output);
            case "skein_1024_384":
                return skein_1024_384(output);
            case "skein_1024_512":
                return skein_1024_512(output);
            case "skein_1024_1024":
                return skein_1024_1024(output);
            case "sm3":
                return sm3(output);
            case "tiger":
                return tiger(output);
            case "md2":
                return md2(output);
            case "md4":
                return md4(output);
            case "md5":
                return md5(output);
            case "gost3411":
                return gost3411(output);
            case "ripemd128":
                return ripemd128(output);
            case "ripemd160":
                return ripemd160(output);
            case "ripemd256":
                return ripemd256(output);
            case "ripemd320":
                return ripemd320(output);
            case "whirlpool":
                return whirlpool(output);
            case "random":
                return random(output, getInt(arguments, 0), getBoolean(arguments, 1));
            case "random_alpha_lower":
                return random_alpha_lower(getInt(arguments, 0));
            case "random_alphanum_lower":
                return random_alphanum_lower(getInt(arguments, 0));
            case "random_alpha_upper":
                return random_alpha_upper(getInt(arguments, 0));
            case "random_alphanum_upper":
                return random_alphanum_upper(getInt(arguments, 0));
            case "random_alpha_mixed":
                return random_alpha_mixed(getInt(arguments, 0));
            case "random_alphanum_mixed":
                return random_alphanum_mixed(getInt(arguments, 0));
            case "random_hex":
                return random_hex(getInt(arguments, 0));
            case "random_hex_mixed":
                return random_hex_mixed(getInt(arguments, 0));
            case "random_num":
                return random_num(getInt(arguments, 0));
            case "random_unicode":
                return random_unicode(getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
            case "range":
                return range(output, getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
            case "total":
                return total(output);
            case "arithmetic":
                return arithmetic(output, getInt(arguments, 0), getString(arguments, 1), getString(arguments, 2));
            case "convert_base":
                return convert_base(output, getString(arguments, 0), getInt(arguments, 1), getInt(arguments, 2));
            case "zeropad":
                return zeropad(output, getString(arguments, 0), getInt(arguments, 1));
            case "behavior":
                return behavior(output);
            case "css_expression":
                return css_expression(output);
            case "datasrc":
                return datasrc(output);
            case "eval_fromcharcode":
                return eval_fromcharcode(output);
            case "iframe_data_url":
                return iframe_data_url(output);
            case "script_data":
                return script_data(output);
            case "uppercase_script":
                return uppercase_script(output);
            case "iframe_src_doc":
                return iframe_src_doc(output);
            case "template_eval":
                return template_eval(output);
            case "throw_eval":
                return throw_eval(output);
            case "python":
                return python(variableMap, output, getString(arguments, 0), getString(arguments, 1), null, customTags);
            case "javascript":
                return javascript(variableMap, output, getString(arguments, 0), getString(arguments, 1), null, customTags);
            case "java":
                return java(variableMap, output, getString(arguments, 0), getString(arguments, 1), null, customTags);
            case "groovy":
                return groovy(variableMap, output, getString(arguments, 0), getString(arguments, 1), null, customTags);
            case "loop_for":
                return loop_for(variableMap, customTags, output, getInt(arguments, 0), getInt(arguments, 1), getInt(arguments, 2), getString(arguments, 3));
            case "loop_letters_lower":
                return loop_letters_lower(variableMap, customTags, output, getString(arguments, 0));
            case "loop_letters_upper":
                return loop_letters_upper(variableMap, customTags, output, getString(arguments, 0));
            case "loop_numbers":
                return loop_letters_numbers(variableMap, customTags, output, getString(arguments, 0));
        }
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
    public static String convert(HashMap<String, String> variables, JSONArray customTags, String input){
        Queue<Element> tagElements;
        try {
            tagElements = HackvertorParser.parse(input);
            return convert(variables, customTags, "", new Stack<>(), tagElements);
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
            tagElements = weakConvertProcessSetTags(variables, customTags, tagElements);
            return weakConvert(variables, customTags, new Stack<>(), tagElements, hackvertor);
        }catch (Exception e){
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            return String.format("Error: %s\n%s", e.getMessage(), sw);
        }
    }

    /**
     * Recursive conversion, ensuring tags are properly matched.
     * Does not treat mismatched tags as text.
     * @param variables
     * @param customTags
     * @param textBuffer
     * @param stack
     * @param elements
     * @return
     * @throws ParseException
     */
    private static String convert(HashMap<String, String> variables,
                                  JSONArray customTags,
                                  String textBuffer,
                                  Stack<Element.StartTag> stack,
                                  Queue<Element> elements) throws ParseException{
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
            String tagOutput = callTag(variables, customTags, selfClosingTag.getIdentifier(), "", selfClosingTag.getArguments(), null);
            textBuffer+= tagOutput;
        }else if(element instanceof Element.StartTag){ //Start of a conversion.
            stack.push((Element.StartTag) element);
            textBuffer+= convert(variables, customTags, "", stack, elements);
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
            return callTag(variables, customTags, startTag.getIdentifier(), textBuffer, startTag.getArguments(), null);
        }

        return convert(variables, customTags, textBuffer, stack, elements);
    }

    private static Queue<Element> weakConvertProcessSetTags(HashMap<String, String> variables,
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

    static String context_url(String properties, Hackvertor hackvertor) {
        if(hackvertor == null) {
            return properties;
        }
        IRequestInfo analyzedRequest = hackvertor.getAnalyzedRequest();
        properties = properties.replace("$protocol", analyzedRequest.getUrl().getProtocol());
        properties = properties.replace("$host", analyzedRequest.getUrl().getHost());
        properties = properties.replace("$path", analyzedRequest.getUrl().getPath());
        properties = properties.replace("$file", analyzedRequest.getUrl().getFile());
        properties = properties.replace("$query", analyzedRequest.getUrl().getQuery());
        properties = properties.replace("$port", String.valueOf(analyzedRequest.getUrl().getPort()));
        return properties;
    }

    static String context_header(String properties, Hackvertor hackvertor) {
        if(hackvertor == null) {
            return properties;
        }
        IRequestInfo analyzedRequest = hackvertor.getAnalyzedRequest();
        List<String> headers = analyzedRequest.getHeaders();
        for(String header : headers) {
            String[] nameValue = header.split(":");
            if(nameValue.length > 1) {
                properties = properties.replace("$" + nameValue[0].trim(), nameValue[1].trim());
            }
        }
        return properties;
    }
    static String context_param(String properties, Hackvertor hackvertor) {
        if(hackvertor == null) {
            return properties;
        }
        IRequestInfo analyzedRequest = hackvertor.getAnalyzedRequest();
        List<IParameter> params = analyzedRequest.getParameters();
        for(IParameter param : params) {
            properties = properties.replace("$"+param.getName(), param.getValue());
        }
        return properties;
    }

    static String context_body(Hackvertor hackvertor) {
        if(hackvertor == null) {
            return "";
        }
        IRequestInfo analyzedRequest = hackvertor.getAnalyzedRequest();
        int bodyOffset = analyzedRequest.getBodyOffset();
        byte[] req = hackvertor.getRequest();
        return helpers.bytesToString(Arrays.copyOfRange(req, bodyOffset, req.length));
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

    static String d_quoted_printable(String str) {
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

    static String fake(String name, String properties, String locale) {
        Faker faker = new Faker(new Locale(locale));
        name = name.replaceFirst("^fake_", "");
        name = name.replaceAll("[^\\w]+","");
        Method[] methods = faker.getClass().getDeclaredMethods();;
        for(Method method : methods) {
            if(Hackvertor.shouldFilterMethod(method)) {
                continue;
            }
            if(!method.getName().equals(name)) {
                continue;
            }
            try {
                Object obj = method.invoke(faker);
                return replaceProperties(obj, replaceProperties(obj, properties));
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }
        return "";
    }

    private static String replaceProperties(Object obj, String properties) {
        Method[] methods = obj.getClass().getDeclaredMethods();
        for(Method method : methods) {
            if(Hackvertor.shouldFilterMethod(method)) {
                continue;
            }
            try {
                properties = properties.replaceAll("\\$"+method.getName(), method.invoke(obj).toString());
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            } catch (InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }
        return properties;
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

    static String substring(String str, int start, int end) {
        try {
            return str.substring(start, end);
        } catch (StringIndexOutOfBoundsException e) {
            return "Invalid index:"+e;
        }
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

    static Boolean isBase64(String str, Boolean checkStart) {
        return Pattern.compile((checkStart ? "^" : "") + "[a-zA-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0;
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
                encodingOpeningTags += "<@gzip_compress>";
                encodingClosingTags = "<@/gzip_compress>" + encodingClosingTags;
            }
            if (Pattern.compile("[01]{4,}\\s+[01]{4,}").matcher(str).find()) {
                str = bin2ascii(str);
                matched = true;
                encodingOpeningTags += "<@ascii2bin>";
                encodingClosingTags = "<@/ascii2bin>" + encodingClosingTags;
            }
            if (Pattern.compile("(?:[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = hex2ascii(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    encodingOpeningTags += "<@ascii2hex(\" \")>";
                    encodingClosingTags = "<@/ascii2hex>" + encodingClosingTags;
                    repeat++;
                    continue;
                }
            }
            if (Pattern.compile("^[0-9a-fA-F]+$").matcher(str).find() && str.length() % 2 == 0) {
                str = hex2ascii(str);
                matched = true;
                encodingOpeningTags += "<@ascii2hex(\"\")>";
                encodingClosingTags = "<@/ascii2hex>" + encodingClosingTags;
            }
            if (!Pattern.compile("[^\\d,\\s]").matcher(str).find() && Pattern.compile("\\d+[,\\s]+").matcher(str).find()) {
                str = from_charcode(str);
                matched = true;
                encodingOpeningTags += "<@to_charcode>";
                encodingClosingTags = "<@/to_charcode>" + encodingClosingTags;
            }
            if (Pattern.compile("(?:\\\\[0]{0,4}[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                test = decode_css_escapes(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@css_escapes>";
                    encodingClosingTags = "<@/css_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\x[0-9a-f]{2}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@hex_escapes>";
                    encodingClosingTags = "<@/hex_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\[0-9]{1,3}").matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@octal_escapes>";
                    encodingClosingTags = "<@/octal_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("\\\\u[0-9a-f]{4}", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                test = decode_js_string(str);
                if (Pattern.compile("^[\\x09-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    encodingOpeningTags += "<@unicode_escapes>";
                    encodingClosingTags = "<@/unicode_escapes>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("&[a-zA-Z]+;", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags += "<@html_entities>";
                encodingClosingTags = "<@/html_entities>" + encodingClosingTags;
            }
            if (Pattern.compile("&#x?[0-9a-f]+;?", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                str = decode_html5_entities(str);
                matched = true;
                tag = "htmlentities";
                encodingOpeningTags += "<@hex_entities>";
                encodingClosingTags = "<@/hex_entities>" + encodingClosingTags;
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
                    encodingClosingTags = "<@/urlencode>" + encodingClosingTags;
                } else {
                    tag = "urlencode_not_plus";
                    encodingOpeningTags += "<@urlencode_not_plus>";
                    encodingClosingTags = "<@/urlencode_not_plus>" + encodingClosingTags;
                }
            }
            if (Pattern.compile("^[a-zA-Z0-9\\-_.]+$", Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                String[] parts = str.split("\\.");
                if (parts.length == 3 && !d_jwt_get_header(str).equals("Invalid token")) {
                    return d_jwt_get_header(str) + "\n" + d_jwt_get_payload(str) + "\n" + decode_base64url(parts[2]);
                }
            }
            if (isBase64(str, false)) {
                test = decode_base64(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base64";
                    encodingOpeningTags += "<@base64>";
                    encodingClosingTags = "<@/base64>" + encodingClosingTags;
                }
            }

            if (Pattern.compile("[A-Z0-9+/]{4,}=*$", Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0 && !matched) {
                test = decode_base32(str);
                if (Pattern.compile("^[\\x00-\\x7f]+$", Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                    str = test;
                    matched = true;
                    tag = "base32";
                    encodingOpeningTags += "<@base32>";
                    encodingClosingTags = "<@/base32>" + encodingClosingTags;
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
                        encodingClosingTags = "<@/rotN>" + encodingClosingTags;
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
                        encodingClosingTags = "<@/affine_encrypt>" + encodingClosingTags;
                    }
                }

                if (Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
                    String plaintext = atbash_decrypt(str);
                    if (is_like_english(plaintext) - is_like_english(str) >= 200) {
                        str = plaintext;
                        matched = true;
                        tag = "atbash";
                        encodingOpeningTags += "<@atbash_encrypt>";
                        encodingClosingTags = "<@/atbash_encrypt>" + encodingClosingTags;
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
                        encodingClosingTags = "<@/rail_fence_encrypt>" + encodingClosingTags;
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
                        encodingClosingTags = "<@/xor>" + encodingClosingTags;
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

    static String python(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags) {
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
            pythonInterpreter.set("executionKey", executionKey);
            pythonInterpreter.set("variableMap", variableMap);
            pythonInterpreter.set("customTags", customTags);
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
                String initCode = "import sys\n" +
                "from burp import BurpExtender\n" +
                "class StreamWrapper(object):\n" +
                "   def __init__(self, wrapped):\n" +
                "       self.__wrapped = wrapped\n" +
                "   def __getattr__(self, name):\n" +
                "       return getattr(self.__wrapped, name)\n" +
                "   def write(self, text):\n" +
                "       BurpExtender.print(text)\n" +
                "orig_stdout = sys.stdout\n" +
                "sys.stdout = StreamWrapper(orig_stdout)\n" +
                "from burp import Convertors\n" +
                "def convert(input):\n" +
                "   return Convertors.convert(variableMap, customTags, input)\n" +
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
            return "Invalid Python code:" + e.toString();
        } catch (Exception e) {
            return "Unable to parse Python:" + e.toString();
        }
    }

    static String java(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags) {
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
        Interpreter javaInterpreter = new Interpreter();
        try {
            javaInterpreter.set("input", input);
            javaInterpreter.set("variableMap", variableMap);
            javaInterpreter.set("executionKey", executionKey);
            javaInterpreter.set("customTags", customTags);
            String initCode = "import burp.Convertors;\n" +
                    "public String convert(String input) {\n" +
                    "   return Convertors.convert(variableMap, customTags, input);\n" +
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
    static String groovy(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags) {
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
        Binding data = new Binding();
        GroovyShell shell = new GroovyShell(data);
        data.setProperty("input", input);
        data.setVariable("variableMap", variableMap);
        data.setVariable("executionKey", executionKey);
        data.setVariable("customTags", customTags);
        String initCode = "import burp.Convertors;\n" +
                "public String convert(String input) {\n" +
                "   return Convertors.convert(variableMap, customTags, input);\n" +
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
    static String javascript(HashMap<String, String> variableMap, String input, String code, String executionKey, JSONObject customTagOptions, JSONArray customTags) {
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
        V8 v8 = V8.createV8Runtime(null, String.valueOf(j2v8TempDirectory));
        String declarations = "var input, output, argument1, argument2";
        Set keySet = variableMap.keySet();
        if(keySet.size() > 0) {
            declarations += "," + keySet.stream().collect(Collectors.joining(","));
        }
        v8.executeScript(declarations);
        v8.add("input", input);
        v8.add("executionKey", executionKey);
        JavaCallback callback = new JavaCallback() {
            public String invoke(final V8Object receiver, final V8Array parameters) {
                if (parameters.length() > 0) {
                    Object input = parameters.get(0);
                    String output = convert(variableMap, customTags, input.toString());
                    if (input instanceof Releasable) {
                        ((Releasable) input).release();
                    }
                    return output;
                }
                return "";
            }
        };
        v8.registerJavaMethod(callback, "convert");
        for (Map.Entry<String, String> entry : variableMap.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            if (name.length() > 0) {
                if(value.matches("^\\d+$")) {
                    v8.add(name, Integer.parseInt(value));
                } else {
                    v8.add(name, value);
                }
            }
        }
        if (customTagOptions != null) {
            JSONObject customTag = (JSONObject) customTagOptions.get("customTag");
            int numberOfArgs = customTag.getInt("numberOfArgs");
            if (numberOfArgs == 1) {
                String name = customTag.getString("argument1");
                String value = customTagOptions.get("param1").toString();
                if(value.matches("^\\d+$")) {
                    v8.add(name, Integer.parseInt(value));
                } else {
                    v8.add(name, value);
                }
            }
            if (numberOfArgs == 2) {
                String argument1Name = customTag.getString("argument1");
                String param1Value = customTagOptions.get("param1").toString();
                if(param1Value.matches("^\\d+$")) {
                    v8.add(argument1Name, Integer.parseInt(param1Value));
                } else {
                    v8.add(argument1Name, param1Value);
                }
                String argument2Name = customTag.getString("argument2");
                String param2Value = customTagOptions.get("param2").toString();
                if(param2Value.matches("^\\d+$")) {
                    v8.add(argument2Name, Integer.parseInt(param2Value));
                } else {
                    v8.add(argument2Name, param2Value);
                }
            }
        }
        try {
            if (code.endsWith(".js")) {
                v8.executeScript(new String(Files.readAllBytes(Paths.get(code)), StandardCharsets.UTF_8));
            } else {
                v8.executeScript(code);
            }
            return v8.get("output").toString();
        } catch (FileNotFoundException e) {
            return "Unable to find JavaScript file:" + e;
        } catch (NullPointerException e) {
            return "Unable to get output. Make sure you have defined an output variable:" + e.toString();
        } catch (AssertionError | Exception e) {
            return "Unable to parse JavaScript:" + e;
        } finally {
            v8.shutdownExecutors(true);
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
            output += convert(variableMap, customTags, input);;
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
