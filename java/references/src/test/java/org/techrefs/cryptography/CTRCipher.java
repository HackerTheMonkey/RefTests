package org.techrefs.cryptography;

import org.apache.commons.lang3.ArrayUtils;
import org.techrefs.gson.cryptography.CryptoFactory;

import static org.techrefs.gson.cryptography.CryptoUtils.toByteArray;

public class CTRCipher {

    public static final int AES_BLOCK_SIZE = 16;
    private byte[] nonce;
    private byte[] iv;
    private byte[] counter;
    private CryptoFactory.Encryptor cipher;
    private String keyBytes;

    public CTRCipher withNonce(String nonce) {
        this.nonce = toByteArray(nonce);
        return this;
    }

    public CTRCipher withIv(String iv) {
        this.iv = toByteArray(iv);
        return this;
    }

    public CTRCipher withInitialCounter(String counter) {
        this.counter = toByteArray(counter);
        return this;
    }

    public CTRCipher withCipher(CryptoFactory.Encryptor cipher) {
        this.cipher = cipher;
        return this;
    }

    public CTRCipher build() throws Exception {
        withCipher(new CryptoFactory().
                fromProvider("BC").
                AES().
                withKeyBytes(keyBytes).
                initialized().
                build());

        return this;
    }

    public byte[] encrypt(byte[] plainText) throws Exception {

        int offset = 0;
        byte[] blockWorthOfPlainText = new byte[AES_BLOCK_SIZE];
        byte[] cipherText = new byte[plainText.length];

        while(offset < plainText.length){

            System.arraycopy(plainText, offset, blockWorthOfPlainText, 0, calculateBytesToCopy(plainText, offset));

            byte[] keyStream = cipher.encrypt(assembleCounterBlock());

            System.arraycopy(XOR(blockWorthOfPlainText, keyStream), 0, cipherText, offset, calculateBytesToCopy(plainText, offset));

            offset += AES_BLOCK_SIZE;
        }


        return cipherText;
    }

    private int calculateBytesToCopy(byte[] plainText, int offset) {
        return (plainText.length - offset) > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : (plainText.length - offset);
    }

    private byte[] XOR(byte[] inputBytes, byte[] counterBlockBytes) {
        byte[] finalOutput = new byte[counterBlockBytes.length];

        for(int i = 0 ; i < finalOutput.length ; i++) {
            finalOutput[i] = (byte) (counterBlockBytes[i] ^ inputBytes[i]);
        }
        return finalOutput;
    }

    private byte[] assembleCounterBlock() {
        return ArrayUtils.addAll(ArrayUtils.addAll(nonce, iv), generateCounter());
    }

    private byte[] generateCounter() {
        for (int i = counter.length - 1; i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
        return counter;
    }

    public CTRCipher withKeyBytes(String keyBytes) {
        this.keyBytes = keyBytes;
        return this;
    }

    public void resetCounter() {
        counter = new byte[4];
    }
}