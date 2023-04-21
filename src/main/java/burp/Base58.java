package burp;

import java.math.BigInteger;

public class Base58 {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }

        // Convert the input bytes to a BigInteger
        BigInteger num = new BigInteger(1, input);

        // Encode the BigInteger as base58
        StringBuilder sb = new StringBuilder();
        while (num.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] qr = num.divideAndRemainder(BASE);
            sb.append(ALPHABET[qr[1].intValue()]);
            num = qr[0];
        }

        // Add leading '1' characters for each leading zero byte in the input
        for (int i = 0; i < input.length && input[i] == 0; i++) {
            sb.append(ALPHABET[0]);
        }

        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }

        // Convert the base58 input to a BigInteger
        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = -1;
            for (int j = 0; j < ALPHABET.length; j++) {
                if (ALPHABET[j] == c) {
                    digit = j;
                    break;
                }
            }
            if (digit == -1) {
                throw new IllegalArgumentException("Invalid character '" + c + "' at position " + i);
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }

        // Convert the BigInteger to a byte array
        byte[] bytes = num.toByteArray();

        // Remove any leading zero bytes
        if (bytes.length > 0 && bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        // Add leading zero bytes for each leading '1' character in the input
        int numZeros = 0;
        for (int i = 0; i < input.length() && input.charAt(i) == ALPHABET[0]; i++) {
            numZeros++;
        }
        byte[] result = new byte[numZeros + bytes.length];
        System.arraycopy(bytes, 0, result, numZeros, bytes.length);

        return result;
    }
}
