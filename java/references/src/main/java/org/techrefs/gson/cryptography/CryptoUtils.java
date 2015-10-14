package org.techrefs.gson.cryptography;

import static java.lang.String.format;

public class CryptoUtils {

    public static final String hexNumbers = "0123456789abcdef";
    public static final String SPACE = " ";

    public static String toHex(byte[] input) {
        StringBuffer stringBuffer = new StringBuffer();

        for (int i = 0; i != input.length; i++) {
            stringBuffer.append(hexNumbers.charAt(Math.abs(input[i] >> 4)));
            stringBuffer.append(hexNumbers.charAt(input[i] & 0x0f));
        }

        return stringBuffer.toString();
    }

    public static String toHex(byte[] input, int length) {
        StringBuffer stringBuffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            stringBuffer.append(hexNumbers.charAt(Math.abs(input[i] >> 4)));
            stringBuffer.append(hexNumbers.charAt(input[i] & 0x0f));
        }

        return stringBuffer.toString();
    }

    public static byte[] toByteArray(String hexString){
        String[] splitted = hexString.split(SPACE);
        byte[] output = new byte[splitted.length];

        for(int i = 0 ; i < splitted.length ; i++) {
            int intermediateValue = Integer.decode(format("0x%s", splitted[i]));
            output[i] = (byte) intermediateValue;
        }

        return output;
    }

}