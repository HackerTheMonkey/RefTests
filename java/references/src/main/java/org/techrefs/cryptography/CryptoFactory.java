package org.techrefs.cryptography;

import lombok.RequiredArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class CryptoFactory {

    private Cipher cipher;
    private String jceProviderName;
    private byte[] keyBytesString;
    private String algorithmName;

    public CryptoFactory AES() throws Exception {
        if(jceProviderName == null) {
            throw new IllegalArgumentException("JCE provider name is required!");
        }
        algorithmName = "AES";
        cipher = Cipher.getInstance("AES/ECB/NoPadding", jceProviderName);
        return this;
    }

    public CryptoFactory withKeyBytes(String keyBytesString) {
        this.keyBytesString = CryptoUtils.toByteArray(keyBytesString);
        return this;
    }

    public CryptoFactory initialized() throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytesString, algorithmName));
        return this;
    }

    public CryptoFactory fromProvider(String jceProviderName) {
        this.jceProviderName = jceProviderName;
        return this;
    }

    public Encryptor build() {
        return new Encryptor(cipher);
    }


    @RequiredArgsConstructor
    public static class Encryptor{
        private final Cipher cipher;

        public byte[] encrypt(byte[] inputBytes) throws Exception {

            byte[] cipherText = new byte[cipher.getOutputSize(inputBytes.length)];
            int bytesEncryptedSoFar = cipher.update(inputBytes, 0, inputBytes.length, cipherText, 0);
            bytesEncryptedSoFar += cipher.doFinal(cipherText, bytesEncryptedSoFar);

            return Arrays.copyOfRange(cipherText, 0, bytesEncryptedSoFar);
        }
    }
}