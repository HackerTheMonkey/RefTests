package org.techrefs.cryptography.book;

import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;

public class ChapterOne {
    @Test
    public void blowfish_encryption_with_64_bit_key_size() throws Exception {
        /**
         * Here is the data that we want to ecnrypt. It has to be a multiple
         * of 8 bytes as per the Blowfish requirement!
         */
        String secretMessage = "hasanein"; //64-bit string
        /**
         * Create a 64-bit symmetric encryption key
         */
        byte[] encryptionKey64bit = "keeeeeey".getBytes();
        SecretKey keySpec = new SecretKeySpec(encryptionKey64bit, "Blowfish");
        /**
         * Create our Cipher that uses Blowfish algorithm and init
         * the cipher with our encryption key
         */
        Cipher blowfishCipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        blowfishCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        /**
         * Now use the Cipher to encrypt our message
         */
        byte[] encryptedMessage = blowfishCipher.doFinal(secretMessage.getBytes());
        System.out.println(encryptedMessage);
        assertThat(encryptedMessage, is(notNullValue()));
    }

    @Test
    public void blowfish_encryption_with_192_bit_key_size() throws Exception {
        /**
         * Here is the data that we want to ecnrypt. It has to be a multiple
         * of 8 bytes as per the Blowfish requirement!
         */
        String secretMessage = "testtest"; //64-bit string
        /**
         * Create a 64-bit symmetric encryption key
         */
        byte[] encryptionKey192bit = new byte[]{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01 };
        SecretKey keySpec = new SecretKeySpec(encryptionKey192bit, "Blowfish");
        /**
         * Create our Cipher that uses Blowfish algorithim and init
         * the cipher with our encryption key
         */
        Cipher blowfishCipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        blowfishCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        /**
         * Now use the Cipher to encrypt our message
         */
        byte[] encryptedMessage = blowfishCipher.doFinal(secretMessage.getBytes());
        System.out.println(encryptedMessage);
        assertThat(encryptedMessage, is(notNullValue()));
    }

    @Test
    public void display_list_of_available_JCE_providers(){
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName());
        }
    }

    @Test
    public void get_the_BouncyCastle_provider(){
        Provider bc = Security.getProvider("BC");
        assertThat(bc, is(notNullValue()));
        System.out.println(bc);
    }

    @Test
    public void determine_what_provider_JRE_selected_for_our_Cipher() throws Exception {
        /**
         * In this case the JRE will automatically select the first
         * provider that has an implementation of the requested algorithim
         */
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        System.out.println(cipher.getProvider());
        /**
         * Or we can create our Cipher asking the JRE to get a specific implementation
         * of an algorithim from a given provider, e.g. BC
         */
        Cipher bc = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC"); //or
        // Cipher bc = Cipher.getInstance("Blowfish/ECB/NoPadding", Security.getProvider("BC")); //or
        System.out.println(bc.getProvider());
    }

    @Test
    public void determine_provider_capabilities() {
        /**
         * Obtain the provider that we are interested in knowing
         * more about what it provides.
         */
        Provider bouncyCastleProvider = Security.getProvider("BC");
        assertThat(bouncyCastleProvider, is(notNullValue()));
        /**
         * Get the KeySet where the provider keep a list of it's
         * capabilities
         */
        Iterator<Object> capabilitiesIterator = bouncyCastleProvider.keySet().iterator();
        while(capabilitiesIterator.hasNext()){
            String capability = (String) capabilitiesIterator.next();

            if(capability.startsWith("Alg.Alias.")) {
                capability = capability.substring("Alg.Alias.".length());
            }

            String factoryClass = capability.substring(0, capability.indexOf("."));
            String name = capability.substring(factoryClass.length() + 1);

            assertThat(factoryClass, is(not(isEmptyOrNullString())));
            assertThat(name, is(not(isEmptyOrNullString())));

            System.out.println(String.format("%s : %s", factoryClass, name));
        }
    }

    /**
     * TODO
     *
     * Write a test that would display the providers our JRE
     * is configured with that supports a particular capability.
     *
     * Or even better, try to incorporate that into a utility.
     */
}
