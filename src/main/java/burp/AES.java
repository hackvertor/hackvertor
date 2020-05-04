package burp;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void setKey(String myKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, IllegalArgumentException {
        MessageDigest sha = null;
        key = myKey.getBytes("UTF-8");
        if(key.length % 16 != 0) {
            throw new IllegalArgumentException("Invalid key length");
        }
        secretKey = new SecretKeySpec(key, "AES");
    }

    public static String encrypt(String strToEncrypt, String secret, String transformations, String iv) throws Exception {
        setKey(secret);
        IvParameterSpec ivSpec = null;
        if(iv.length() > 0 ) {
            ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        }
        Cipher cipher = Cipher.getInstance(transformations);
        if(iv.length() > 0) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
    }

    public static String decrypt(String strToDecrypt, String secret, String transformations, String iv) throws Exception {
        setKey(secret);
        IvParameterSpec ivSpec = null;
        if(iv.length() > 0 ) {
            ivSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        }
        Cipher cipher = Cipher.getInstance(transformations);
        if(iv.length() > 0) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    }
}