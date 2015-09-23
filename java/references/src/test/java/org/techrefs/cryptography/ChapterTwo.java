package org.techrefs.cryptography;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.techrefs.gson.cryptography.CryptoUtils.toHex;

// It's too verbose and ugly code, cause I am still learning and like to type the API repeatedly
// Clean code will make me right less, so not doing it while in learning mode.
// My intention here is to learn the underlying principles rather than how to code, which I consider myself very good at
@Slf4j
public class ChapterTwo {

    @Test
    public void some_basic_encryption_decryption_using_AES_ECB_withNoPadding() throws Exception{

        // here is our secret message that we want to keep it from others' eyes.
        byte[] inputData = new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               (byte) 0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc,
                               (byte) 0xdd, (byte) 0xee, (byte)0xff
        };

        // some fixed bytes to use as our symmetric encryption/decryption key
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

        /**
         * Let's create a SecretKeySpec out of the keyBytes. This should be specific
         * to the algirithm that the key is going to be used with.
         */
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        /**
         * Now we need to create our Cipher for the desired algorithm. We have to explictly tell
         * JCE/JCA which provider we want the implementation of the algorithm to be obtained from. In this
         * particular case we are going to choose the BouncyCastle, BC, provider.
         */
        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        System.out.println(String.format("inputData: %s, length: %s", toHex(inputData), inputData.length));

        /**
         * Let's create an array that is going to contain our cipher text. As we are not
         * using any padding, then the size of the array should be the same as the size
         * of our input plain text.
         */
        byte[] cipherText = new byte[inputData.length];
        /**
         * in order to use the Cipher, we have to initialize it prior to any attempt
         * to use it to encrypt or decrypt anything.
         */
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        /**
         * Let's start with the encryption process, part 1
         */
        int cipherTextLength = aesCipher.update(inputData, 0, inputData.length, cipherText, 0);
        /**
         * finish it off
         */
        cipherTextLength += aesCipher.doFinal(cipherText, cipherTextLength);
        System.out.println(String.format("encryptedData: %s, length: %s", toHex(cipherText), cipherTextLength));
        /**
         * Let's attempt to decrypt the data that we have just encrypted
         * Start by creating a byte array that will end up containing our
         * deciphered text. The length of which should be no more than the
         * length of the ciphered text
         */
        byte[] plainText = new byte[cipherTextLength];
        /**
         * Let's reuse our instance of the Cipher by re-configure
         * it to operate in decrypt mode for us
         */
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        /**
         * Let's kick start the decryption process.
         */
        int plainTextLength = aesCipher.update(cipherText, 0, cipherText.length, plainText);
        plainTextLength += aesCipher.doFinal(plainText, plainTextLength);
        /**
         * Let's print out the result and make sure that we have got back what we encrypted
         * in the first place.
         */
        System.out.println(String.format("plainText: %s, length: %s", toHex(plainText), plainTextLength));
        assertThat(plainText, is(inputData));
    }

    @Test
    public void lets_do_some_AES_encryption_for_some_data_that_requires_padding() throws Exception{

        /**
         * As our input data is 50% larger than the block size of AES, which is 16Bytes, then
         * this will require us to alter the transformation of the Cipher to use some sort of
         * padding to compensate for the alignment deficit. One padding mechanism that we can
         * utilize here is PKCS7Padding
         *
         */
        // here is our secret message that we want to keep it from others' eyes.
        byte[] inputData = new byte[]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x0a, 0x0b, 0x0c
                , 0x0d, 0x0e, 0x0f, 0x10, 0x20, 0x30 ,0x40, 0x50, 0x60, 0x70, 0x10, 0x11};

        // some fixed bytes to use as our symmetric encryption/decryption key
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

        /**
         * Let's create a SecretKeySpec out of the keyBytes. This should be specific
         * to the algirithm that the key is going to be used with.
         */
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        /**
         * Now we need to create our Cipher for the desired algorithm. We have to explictly tell
         * JCE/JCA which provider we want the implementation of the algorithm to be obtained from. In this
         * particular case we are going to choose the BouncyCastle, BC, provider.
         */
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        System.out.println(String.format("inputData: %s, length: %s", toHex(inputData), inputData.length));

        /**
         * in order to use the Cipher, we have to initialize it prior to any attempt
         * to use it to encrypt or decrypt anything. We are going to initialize the Cipher
         * prior to creating our output array as we are relying on the Cipher to determine the
         * initial size of the array and any interaction with the Cipher prior to it's initialization
         * will result in an exception to br thrown.
         */
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        /**
         * Let's create an array that is going to contain our cipher text. As we are using some sort of
         * a padding mechanisim, then we are not totally sure as to what size the array should be created with. Hence,
         * we are going to ask the Cipher to tell us how big our output bucket should be.
         */
        byte[] cipherText = new byte[aesCipher.getOutputSize(inputData.length)];
        /**
         * Let's start with the encryption process, part 1
         */
        int cipherTextLength = aesCipher.update(inputData, 0, inputData.length, cipherText, 0);
        /**
         * finish it off
         */
        cipherTextLength += aesCipher.doFinal(cipherText, cipherTextLength);
        System.out.println(String.format("encryptedData: %s, length: %s", toHex(cipherText), cipherTextLength));

        /**
         * Let's reuse our instance of the Cipher by re-configure
         * it to operate in decrypt mode for us
         */
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        /**
         * Let's attempt to decrypt the data that we have just encrypted
         * Start by creating a byte array that will end up containing our
         * deciphered text. The length of which should be no more than the
         * length of the ciphered text
         */
        byte[] plainText = new byte[aesCipher.getOutputSize(cipherText.length)];
        /**
         * Let's kick start the decryption process.
         */
        int plainTextLength = aesCipher.update(cipherText, 0, cipherText.length, plainText);
        plainTextLength += aesCipher.doFinal(plainText, plainTextLength);
        /**
         * Let's print out the result and make sure that we have got back what we encrypted
         * in the first place.
         */
        System.out.println(String.format("plainText: %s, length: %s", toHex(plainText, plainTextLength), plainTextLength));
        assertThat(toHex(plainText, plainTextLength), is(toHex(inputData)));
    }


    @Test
    public void using_ECB_mode_with_a_repeatable_input_data_might_result_in_having_recognizable_patterns_in_the_encrypted_data() throws Exception {
        /**
         * As ECB is the closest mode to the cipher used with and the fact that it represents the rawest form of operation
         * of the given cipher, then encrypting structured data or data that contain repeating patterns might result in
         * a very similar pattern to unfold when closely looking at the encrypted version of the data which might tell
         * a malicious attacker a lot more about the underlying data being encrypted.
         */

        // craft a repeatable input data by hand
        byte[] inputData = "{{{{{{{{{{{{{{{a:b, c:d{{{{{{{{{{{{{{{qwkljehlkqhwelkqwhelkqhwe {{{{{{{{{{{{{{{, f:{}{{{{{{{{{{{{{{{}".getBytes();
//        byte[] inputData = new byte[]{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x11, 0x22, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

        // manually create the SecretKeySpec to be used for DES, the max limit for DES key is 64 bits (8 Bytes)
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        // create the Cipher, don't forget to ask for a very specific provider where your cipher objects implementation
        // comes from.
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS7Padding", "BC");

        // init the Cipher
        desCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // Ask the Cipher for an estimation of how big the output data going to be!
        // remember that this still an estimation and the real data might be much less
        byte[] encryptedText = new byte[desCipher.getOutputSize(inputData.length)];

        // encrypt the data - Stage 1
        int bytesWrittenByCipherSoFar = desCipher.update(inputData, 0, inputData.length, encryptedText, 0);

        // Finish off the encryption process - Stage 2
        bytesWrittenByCipherSoFar += desCipher.doFinal(encryptedText, bytesWrittenByCipherSoFar);

        // Print out for comparision
        System.out.println(String.format("InputData: %s, Length: %s", toHex(inputData), inputData.length));
        System.out.println(String.format("EncryptedData: %s, Length: %s", toHex(encryptedText), bytesWrittenByCipherSoFar));

        // Decrypt back into the initial plain text
        desCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Ask the Cipher for the expected size of the cipher text
        byte[] decryptedData = new byte[desCipher.getOutputSize(bytesWrittenByCipherSoFar)];

        // initial stage of decryption
        int bytesDecryptedSoFar = desCipher.update(encryptedText, 0, bytesWrittenByCipherSoFar, decryptedData, 0);

        // final kick to decrypt
        bytesDecryptedSoFar += desCipher.doFinal(decryptedData, bytesDecryptedSoFar);

        // print out for comparision
        System.out.println(String.format("DecryptedData: %s, Length: %s", toHex(decryptedData), bytesDecryptedSoFar));
    }

    @Test
    public void using_DES_with_CBC_mode_to_overcome_the_issue_with_noticable_patterns_we_faced_with_ECB_mode() throws Exception {
        /**
         * The CBC mode overcome the problem that we have faced with ECB by XORing each block of data with the one
         * that comes before it. As for the very first block of data, nothing have been encrypted at that stage, for
         * that we need to provide some sort of seed data to be used for XORing the first block of data, this
         * data is to be called the Iv, or the Initialization Vector and have to be of the same size of the block
         * that it will be XORed with.
         */
        // craft a repeatable input data by hand
        // as we are using padding, we don't really care how big our input data is.
        String inputString = "{\"fields\":null,\"metrics\":null,\"offset\":0,\"rows\":null,\"dimensions\":null,\"search_terms\":{\"merchant_id\":\"3176752955\"},\"total_element_number\":1000,\"start_date\":\"20140903\",\"end_date\":\"20140905\",\"limits\":10,\"sort_by\":null,\"transactions\":[{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"563\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"996172\",\"transaction_amount\":882,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":415,\"cashback_reference\":\"674703023166\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"488\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"477681\",\"transaction_amount\":275,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":913,\"cashback_reference\":\"765708921343\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"612\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"926289\",\"transaction_amount\":612,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":548,\"cashback_reference\":\"677019189957\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"839\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"652620\",\"transaction_amount\":879,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":360,\"cashback_reference\":\"307430443134\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"136\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"393604\",\"transaction_amount\":282,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":623,\"cashback_reference\":\"853023050160\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"151\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"769244\",\"transaction_amount\":507,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":913,\"cashback_reference\":\"491467409269\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"997\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"923813\",\"transaction_amount\":208,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":967,\"cashback_reference\":\"438437285231\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"511\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"212888\",\"transaction_amount\":429,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":693,\"cashback_reference\":\"360406206550\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"208\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"917811\",\"transaction_amount\":672,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":235,\"cashback_reference\":\"376865211965\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"788\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"438563\",\"transaction_amount\":178,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":522,\"cashback_reference\":\"726637289296\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"}],\"column_headers\":null}";
        System.out.println("InputString: " + inputString);

        byte[] inputData = inputString.getBytes();

        // create the KeySpec, really simple 64bit key
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        // let's not forget the IV, the size of which must match the block size of the algorithm used.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});

        // create the Cipher and initialize it
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        // create the output bucket, we need to ask Cipher about how big he think it should be
        byte[] cipherText = new byte[cipher.getOutputSize(inputData.length)];

        // encrypt
        int bytesCipheredSoFar = cipher.update(inputData, 0, inputData.length, cipherText, 0);
        bytesCipheredSoFar += cipher.doFinal(cipherText, bytesCipheredSoFar);

        // print it out
        System.out.println(String.format("PlainText: %s, Length: %s", toHex(inputData), inputData.length));
        System.out.println(String.format("CipheredText: %s, Length: %s", toHex(cipherText), bytesCipheredSoFar));

        // init the cipher for decryption preparation, don't forget the IV
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Create the output bucket for the decipherd text, but let's ask cipher how big he think the output bucket should be for the decipheredText
        byte[] decipheredText = new byte[cipher.getOutputSize(bytesCipheredSoFar)];

        // decrypt
        int bytesDecipheredSoFar = cipher.update(cipherText, 0, bytesCipheredSoFar, decipheredText, 0);
        bytesDecipheredSoFar += cipher.doFinal(decipheredText, bytesDecipheredSoFar);

        // print it out
        System.out.println(String.format("DecipheredText: %s, Length: %s", toHex(decipheredText, bytesDecipheredSoFar), bytesDecipheredSoFar));

        // The comparision should ignore any padding that has been added and only consider the actual bytes written
        // by the cipher.
        assertThat(Arrays.copyOf(decipheredText, bytesDecipheredSoFar), is(inputData));

        // print out a string representation of the deciphered text to see if it results in our original data.
        System.out.println("decrypted output String" + new String(Arrays.copyOf(decipheredText, bytesDecipheredSoFar)));
    }

    @Test(expected = InvalidKeyException.class)// aparently we have to provide an IV if out cipher needs it.
    public void using_DES_with_CBC_mode_but_not_providing_an_IV_to_see_what_happens() throws Exception {

        /**
         * Not providing an IV while using a Cipher with a mode that neccessitates one seem to result in
         * throwing an exception complaining that we have not provided an IV while one is expected.
         */

        // craft a repeatable input data by hand
        // as we are using padding, we don't really care how big our input data is.
        String inputString = "{\"fields\":null,\"metrics\":null,\"offset\":0,\"rows\":null,\"dimensions\":null,\"search_terms\":{\"merchant_id\":\"3176752955\"},\"total_element_number\":1000,\"start_date\":\"20140903\",\"end_date\":\"20140905\",\"limits\":10,\"sort_by\":null,\"transactions\":[{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"563\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"996172\",\"transaction_amount\":882,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":415,\"cashback_reference\":\"674703023166\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"488\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"477681\",\"transaction_amount\":275,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":913,\"cashback_reference\":\"765708921343\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"612\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"926289\",\"transaction_amount\":612,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":548,\"cashback_reference\":\"677019189957\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"839\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"652620\",\"transaction_amount\":879,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":360,\"cashback_reference\":\"307430443134\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"136\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"393604\",\"transaction_amount\":282,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":623,\"cashback_reference\":\"853023050160\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"151\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"769244\",\"transaction_amount\":507,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":913,\"cashback_reference\":\"491467409269\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"997\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"923813\",\"transaction_amount\":208,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":967,\"cashback_reference\":\"438437285231\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"511\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"212888\",\"transaction_amount\":429,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":693,\"cashback_reference\":\"360406206550\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"208\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"917811\",\"transaction_amount\":672,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":235,\"cashback_reference\":\"376865211965\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"},{\"merchant_id\":\"3176752955\",\"merchant_name\":\"JOE SMITH MERCHANT\",\"transaction_status\":\"PROCESSED\",\"terminal_id\":\"788\",\"transaction_type_desc\":\"SALE\",\"transaction_mode_desc\":\"Manual\",\"card_type\":\"C\",\"transaction_date\":1409702400000,\"transaction_response_code\":\"some transaction resp code\",\"transaction_response_code_desc\":\"APPROVAL\",\"cashback_amount\":\"0\",\"auth_code\":\"438563\",\"transaction_amount\":178,\"pc_entry_mode_desc\":\"MANUAL/KEY ENTERED\",\"auth_amount\":522,\"cashback_reference\":\"726637289296\",\"reject_reason\":\"some reject reason\",\"product_code\":\"00000\",\"product_code_abv\":\"VISA\",\"product_code_category\":\"CREDIT\",\"currency_code_abv\":\"USD\",\"card_usage\":\"some value\",\"transaction_service_code\":\"-1\",\"auth_terminal_id\":\"some value\",\"store_nbr\":\"some value\",\"transaction_auth_type\":\"-1\",\"transaction_auth_type_desc\":\"UNKNOWN TRANSACTION\",\"tpp_id\":\"some value\",\"cvv_err\":\"some value\",\"validation_cd\":\"some value\",\"transaction_tag\":\"some value\",\"eci_indicator\":\"some value\",\"order_number\":\"some value\",\"txn_type_indicator\":\"S\",\"transaction_date_iso8601\":\"2014-09-03T00:00Z\"}],\"column_headers\":null}";
        System.out.println("InputString: " + inputString);

        byte[] inputData = inputString.getBytes();

        // create the KeySpec, really simple 64bit key
        SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07}, "DES");

        // create the Cipher and initialize it
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // create the output bucket, we need to ask Cipher about how big he think it should be
        byte[] cipherText = new byte[cipher.getOutputSize(inputData.length)];

        // encrypt
        int bytesCipheredSoFar = cipher.update(inputData, 0, inputData.length, cipherText, 0);
        bytesCipheredSoFar += cipher.doFinal(cipherText, bytesCipheredSoFar);

        // print it out
        System.out.println(String.format("PlainText: %s, Length: %s", toHex(inputData), inputData.length));
        System.out.println(String.format("CipheredText: %s, Length: %s", toHex(cipherText), bytesCipheredSoFar));

        // init the cipher for decryption preparation, don't forget the IV
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Create the output bucket for the decipherd text, but let's ask cipher how big he think the output bucket should be for the decipheredText
        byte[] decipheredText = new byte[cipher.getOutputSize(bytesCipheredSoFar)];

        // decrypt
        int bytesDecipheredSoFar = cipher.update(cipherText, 0, bytesCipheredSoFar, decipheredText, 0);
        bytesDecipheredSoFar += cipher.doFinal(decipheredText, bytesDecipheredSoFar);

        // print it out
        System.out.println(String.format("DecipheredText: %s, Length: %s", toHex(decipheredText, bytesDecipheredSoFar), bytesDecipheredSoFar));

        // The comparision should ignore any padding that has been added and only consider the actual bytes written
        // by the cipher.
        assertThat(Arrays.copyOf(decipheredText, bytesDecipheredSoFar), is(inputData));

        // print out a string representation of the deciphered text to see if it results in our original data.
        System.out.println("decrypted output String" + new String(Arrays.copyOf(decipheredText, bytesDecipheredSoFar)));
    }

    @Test
    public void using_DES_with_CBC_mode_but_this_time_we_are_going_to_have_an_inline_iv_and_a_seed_ciphered_block() throws Exception {
        /**
         * As an alternative to providing a fixed IV in an out of band fashion, we can expect that the IV will be
         * provided alongside the message and it's the responsibility of us to read past it when encrypting and
         * decryoting.
         */

        // This is out input message, in plain text
        byte[] input = "{foo: bar, x:dd }".getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // manually set the DES key
        SecretKeySpec key = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        // we need an all-zero IV to start with
        IvParameterSpec allZeroIV = new IvParameterSpec(new byte[8]);

        // the inline IV bytes that we are assuming they have been sent to us with the plain text to encrypt
        // the size of these should conform to the size of the underlying algorithm block
        byte[] ivBytes = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, (byte) 0x87};

        // get an instance of a DES Cipher and initialize it for encryption
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, allZeroIV);

        // let's ask the cipher about what he thinks the size of our output bucket should be
        int totalMessageSize = ivBytes.length + input.length; // iv + plain text payload
        byte[] cipheredText = new byte[cipher.getOutputSize(totalMessageSize)];

        // let's encrypt, shall we?
        int numberOfEncryptedBytes = cipher.update(ivBytes, 0, ivBytes.length, cipheredText, 0);
        numberOfEncryptedBytes += cipher.update(input, 0, input.length, cipheredText, numberOfEncryptedBytes);
        numberOfEncryptedBytes += cipher.doFinal(cipheredText, numberOfEncryptedBytes);
        log.info("CipheredText: {}, Length: {} bytes", toHex(cipheredText, numberOfEncryptedBytes), numberOfEncryptedBytes);

        // decrypt all that

        // Consult the cipher as how big our decryption buffer should be
        byte[] decryptionBuffer = new byte[cipher.getOutputSize(numberOfEncryptedBytes)];

        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, allZeroIV);

        // at the end of this, the decryptionBuffer will contain the initial IV + our plain text
        int bytesDecryptedSoFar = cipher.update(cipheredText, 0, numberOfEncryptedBytes, decryptionBuffer, 0);
        bytesDecryptedSoFar += cipher.doFinal(decryptionBuffer, bytesDecryptedSoFar);

        // retrieve the plainText message out of the decryption buffer
        byte[] plainText = new byte[bytesDecryptedSoFar - ivBytes.length];
        System.arraycopy(decryptionBuffer, ivBytes.length, plainText, 0, plainText.length);

        log.info("PlainText: {}, Length: {} Bytes", new String(plainText), plainText.length);
        log.info("PlainText: {}, Length: {} Bytes", toHex(plainText), plainText.length);

        assertThat(plainText, is(input));
    }

    @Test
    public void use_java_SecureRandom_to_aid_in_creating_a_random_IV() throws Exception {
        // construct the input
        byte[] input = "{foo: bar, x:dd }".getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // manually set the DES key
        SecretKeySpec key = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        /**
         * A random IV need to be created, we are going to use an implementation
         * og Java's SecureRandom to obtain a random number
         */
        byte[] randomIvBytes = new byte[8];

        // generate the random numbers
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(randomIvBytes);

        // use them to feed the IV generation
        IvParameterSpec randomIV = new IvParameterSpec(randomIvBytes);


        // get an instance of a DES Cipher and initialize it for encryption
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, randomIV);

        // let's ask the cipher about what he thinks the size of our output bucket should be
        byte[] cipheredText = new byte[cipher.getOutputSize(input.length)];

        // let's encrypt, shall we?
        int numberOfEncryptedBytes = cipher.update(input, 0, input.length, cipheredText, 0);
        numberOfEncryptedBytes += cipher.doFinal(cipheredText, numberOfEncryptedBytes);
        log.info("CipheredText: {}, Length: {} bytes", toHex(cipheredText, numberOfEncryptedBytes), numberOfEncryptedBytes);

        // decrypt all that

        // Consult the cipher as how big our decryption buffer should be
        byte[] plainText = new byte[cipher.getOutputSize(numberOfEncryptedBytes)];

        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, randomIV);

        // let's decrypt
        int bytesDecryptedSoFar = cipher.update(cipheredText, 0, numberOfEncryptedBytes, plainText, 0);
        bytesDecryptedSoFar += cipher.doFinal(plainText, bytesDecryptedSoFar);

        log.info("PlainText: {}, Length: {} Bytes", new String(Arrays.copyOfRange(plainText, 0, bytesDecryptedSoFar)), bytesDecryptedSoFar);
        log.info("PlainText: {}, Length: {} Bytes", toHex(plainText, bytesDecryptedSoFar), bytesDecryptedSoFar);

        // Make sure that what we have decrypted is exactly the same as out plain text input
        assertThat(Arrays.copyOfRange(plainText, 0, bytesDecryptedSoFar), is(input));
    }

    @Test
    public void use_java_SecureRandom_with_SHA1PRNG_to_aid_in_creating_a_random_IV() throws Exception {
        // construct the input
        byte[] input = "{foo: bar, x:dd }".getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // manually set the DES key
        SecretKeySpec key = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        /**
         * A random IV need to be created, we are going to use an implementation
         * of Java's SecureRandom to obtain a random number
         */
        byte[] randomIvBytes = new byte[8];

        // generate the random numbers
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        log.info("Selected PRNG provider is {}", secureRandom.getProvider().getName());
        secureRandom.nextBytes(randomIvBytes);

        // use them to feed the IV generation
        IvParameterSpec randomIV = new IvParameterSpec(randomIvBytes);

        // get an instance of a DES Cipher and initialize it for encryption
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, randomIV);

        // let's ask the cipher about what he thinks the size of our output bucket should be
        byte[] cipheredText = new byte[cipher.getOutputSize(input.length)];

        // let's encrypt, shall we?
        int numberOfEncryptedBytes = cipher.update(input, 0, input.length, cipheredText, 0);
        numberOfEncryptedBytes += cipher.doFinal(cipheredText, numberOfEncryptedBytes);
        log.info("CipheredText: {}, Length: {} bytes", toHex(cipheredText, numberOfEncryptedBytes), numberOfEncryptedBytes);

        // decrypt all that

        // Consult the cipher as how big our decryption buffer should be
        byte[] plainText = new byte[cipher.getOutputSize(numberOfEncryptedBytes)];

        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, randomIV);

        // let's decrypt
        int bytesDecryptedSoFar = cipher.update(cipheredText, 0, numberOfEncryptedBytes, plainText, 0);
        bytesDecryptedSoFar += cipher.doFinal(plainText, bytesDecryptedSoFar);

        log.info("PlainText: {}, Length: {} Bytes", new String(Arrays.copyOfRange(plainText, 0, bytesDecryptedSoFar)), bytesDecryptedSoFar);
        log.info("PlainText: {}, Length: {} Bytes", toHex(plainText, bytesDecryptedSoFar), bytesDecryptedSoFar);

        // Make sure that what we have decrypted is exactly the same as out plain text input
        assertThat(Arrays.copyOfRange(plainText, 0, bytesDecryptedSoFar), is(input));
    }

    @Test
    public void lets_create_an_IV_out_of_a_message_number_chosen_as_nonce() throws Exception {
        // construct the input

        String inputText = "{foo: bar, x:dd }";

        byte[] input = inputText.getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // All ZEROs IV to use to generate the encryption IV
        byte[] allZeroIVBytes = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

        // our unique message number, somehting really simple that we ar happy to consider as a NONCE
        byte[] messageNumber = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

        // here is our DES key
        SecretKeySpec key = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        /**
         * IV generation from the message number
         */
        // Generate an IV via using a message number as a NONCE
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

        // Init the cipher for encryption, i.e. Initial IV generation
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(allZeroIVBytes));

        // Generate our IV to be used for encryption (by encrypting the message number)
        IvParameterSpec encryptionIV = new IvParameterSpec(cipher.doFinal(messageNumber), 0, 8);
        log.info("IV generated from the message number {}, length: {}", toHex(encryptionIV.getIV()), encryptionIV.getIV().length);

        /**
         * Input message encryption
         */
        // re-init the cipher for encryption, using the newly generated IV
        cipher.init(Cipher.ENCRYPT_MODE, key, encryptionIV);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int bytesEncrypted = cipher.update(input, 0, input.length, cipherText, 0);
        bytesEncrypted += cipher.doFinal(cipherText, bytesEncrypted);

        log.info("CipherText: {}, Length: {}", toHex(cipherText), bytesEncrypted);

        /**
         * Cipher test decryption
         */
        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, encryptionIV);

        byte[] decryptedData = new byte[cipher.getOutputSize(bytesEncrypted)];
        int bytesDecrypted = cipher.update(cipherText, 0, bytesEncrypted, decryptedData, 0);
        bytesDecrypted += cipher.doFinal(decryptedData, bytesDecrypted);

        log.info("deCipheredText: {}, Length: {}", toHex(decryptedData, bytesDecrypted), bytesDecrypted);
        log.info("plainText: {}, Length: {}", new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), Arrays.copyOfRange(decryptedData, 0, bytesDecrypted).length);

        /**
         * Making sure that the decrypted message is the same as the initial plain text
         */
        assertThat(new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), is(inputText));
    }

    @Test
    public void lets_do_a_bit_of_DES_with_CTS_mode() throws Exception{

        // construct the input
        String inputText = "{foo: bar, x:dd }";

        byte[] input = inputText.getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // Some bytes to be used for our IV
        byte[] ivBytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

        // here is our DES key
        SecretKeySpec key = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "DES");

        // Get an instance of our cipher. this time using CTS mode.
        // This mode doesn't require any paddings, and it should produce
        // a cipher text that is the same length of the input plain text.
        Cipher cipher = Cipher.getInstance("DES/CTS/NoPadding", "BC");

        // Create an IV out of the IVBytes
        IvParameterSpec encryptionIV = new IvParameterSpec(ivBytes);

        /**
         * Input message encryption
         */
        // re-init the cipher for encryption, using the newly generated IV
        cipher.init(Cipher.ENCRYPT_MODE, key, encryptionIV);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int bytesEncrypted = cipher.update(input, 0, input.length, cipherText, 0);
        bytesEncrypted += cipher.doFinal(cipherText, bytesEncrypted);

        log.info("CipherText: {}, Length: {}", toHex(cipherText), bytesEncrypted);

        /**
         * Let's make sure that the size of the cipher text is the same as the
         * size of the input data, despite not using any padding as we are using
         * CTS mode.
         */
        assertThat(input.length, is(bytesEncrypted));
        /**
         * Cipher test decryption
         */
        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, encryptionIV);

        byte[] decryptedData = new byte[cipher.getOutputSize(bytesEncrypted)];
        int bytesDecrypted = cipher.update(cipherText, 0, bytesEncrypted, decryptedData, 0);
        bytesDecrypted += cipher.doFinal(decryptedData, bytesDecrypted);

        log.info("deCipheredText: {}, Length: {}", toHex(decryptedData, bytesDecrypted), bytesDecrypted);
        log.info("plainText: {}, Length: {}", new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), Arrays.copyOfRange(decryptedData, 0, bytesDecrypted).length);

        /**
         * Making sure that the decrypted message is the same as the initial plain text
         */
        assertThat(new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), is(inputText));
    }

    @Test
    public void AES_in_CTS_mode() throws Exception{

        // construct the input
        String inputText = "{foo: bar, x:dd, y:hah }";

        byte[] input = inputText.getBytes();
        log.info("InputData: {}, Length: {} bytes", new String(input), input.length);
        log.info("InputData: {}, Length: {} bytes", toHex(input), input.length);

        // IV has to match the block size of the underlying encryption algorithm, which is 16 Bytes for AES
        byte[] ivBytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};

        // here is our DES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();

        // Get an instance of our cipher. this time using CTS mode.
        // This mode doesn't require any paddings, and it should produce
        // a cipher text that is the same length of the input plain text.
        Cipher cipher = Cipher.getInstance("AES/CTS/NoPadding", "BC");

        // Create an IV out of the IVBytes
        IvParameterSpec encryptionIV = new IvParameterSpec(ivBytes);

        /**
         * Input message encryption
         */
        // re-init the cipher for encryption, using the newly generated IV
        cipher.init(Cipher.ENCRYPT_MODE, key, encryptionIV);

        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

        int bytesEncrypted = cipher.update(input, 0, input.length, cipherText, 0);
        bytesEncrypted += cipher.doFinal(cipherText, bytesEncrypted);

        log.info("CipherText: {}, Length: {}", toHex(cipherText), bytesEncrypted);

        /**
         * Let's make sure that the size of the cipher text is the same as the
         * size of the input data, despite not using any padding as we are using
         * CTS mode.
         */
        assertThat(input.length, is(bytesEncrypted));
        /**
         * Cipher test decryption
         */
        // re-init the cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, key, encryptionIV);

        byte[] decryptedData = new byte[cipher.getOutputSize(bytesEncrypted)];
        int bytesDecrypted = cipher.update(cipherText, 0, bytesEncrypted, decryptedData, 0);
        bytesDecrypted += cipher.doFinal(decryptedData, bytesDecrypted);

        log.info("deCipheredText: {}, Length: {}", toHex(decryptedData, bytesDecrypted), bytesDecrypted);
        log.info("plainText: {}, Length: {}", new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), Arrays.copyOfRange(decryptedData, 0, bytesDecrypted).length);

        /**
         * Making sure that the decrypted message is the same as the initial plain text
         */
        assertThat(new String(Arrays.copyOfRange(decryptedData, 0, bytesDecrypted)), is(inputText));
    }

    /**
     * TODO
     * - research the possible ways in which we can create a SecureRandom number and the differnces
     * among these methods as well as what do they mean and what particular instance/implementation
     * of the RNG algorithim is being returned by the JDK
     */

}