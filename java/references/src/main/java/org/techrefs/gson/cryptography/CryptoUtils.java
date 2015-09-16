package org.techrefs.gson.cryptography;

public class CryptoUtils {

    public static final String hexNumbers = "0123456789abcdef";

    public static String toHex(byte[] input){
        StringBuffer stringBuffer = new StringBuffer();

        for(int i = 0 ; i != input.length ; i++) {
            stringBuffer.append(hexNumbers.charAt(Math.abs(input[i] >> 4)));
            stringBuffer.append(hexNumbers.charAt(input[i] & 0x0f));
        }

        return stringBuffer.toString();
    }

    public static String toHex(byte[] input, int length){
        StringBuffer stringBuffer = new StringBuffer();

        for(int i = 0 ; i != length ; i++) {
            stringBuffer.append(hexNumbers.charAt(Math.abs(input[i] >> 4)));
            stringBuffer.append(hexNumbers.charAt(input[i] & 0x0f));
        }

        return stringBuffer.toString();
    }

}
