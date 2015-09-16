package org.techrefs.cryptography;

import org.junit.Test;
import org.techrefs.gson.cryptography.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.techrefs.gson.cryptography.CryptoUtils.toHex;

// It's too verbose and ugly code, cause I am still learning and like to type the API repeatedly
// Clean code will make me right less, so not doing it while in learning mode.
// My intention here is to learn the underlying principles rather than how to code, which I consider myself very good at
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
        System.out.println(String.format("InputData: %s, Length: %s", CryptoUtils.toHex(inputData), inputData.length));
        System.out.println(String.format("EncryptedData: %s, Length: %s", CryptoUtils.toHex(encryptedText), bytesWrittenByCipherSoFar));

        // Decrypt back into the initial plain text
        desCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Ask the Cipher for the expected size of the cipher text
        byte[] decryptedData = new byte[desCipher.getOutputSize(bytesWrittenByCipherSoFar)];

        // initial stage of decryption
        int bytesDecryptedSoFar = desCipher.update(encryptedText, 0, bytesWrittenByCipherSoFar, decryptedData, 0);

        // final kick to decrypt
        bytesDecryptedSoFar += desCipher.doFinal(decryptedData, bytesDecryptedSoFar);

        // print out for comparision
        System.out.println(String.format("DecryptedData: %s, Length: %s", CryptoUtils.toHex(decryptedData), bytesDecryptedSoFar));
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
        System.out.println(String.format("PlainText: %s, Length: %s", CryptoUtils.toHex(inputData), inputData.length));
        System.out.println(String.format("CipheredText: %s, Length: %s", CryptoUtils.toHex(cipherText), bytesCipheredSoFar));

        // init the cipher for decryption preparation, don't forget the IV
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        // Create the output bucket for the decipherd text, but let's ask cipher how big he think the output bucket should be for the decipheredText
        byte[] decipheredText = new byte[cipher.getOutputSize(bytesCipheredSoFar)];

        // decrypt
        int bytesDecipheredSoFar = cipher.update(cipherText, 0, bytesCipheredSoFar, decipheredText, 0);
        bytesDecipheredSoFar += cipher.doFinal(decipheredText, bytesDecipheredSoFar);

        // print it out
        System.out.println(String.format("DecipheredText: %s, Length: %s", CryptoUtils.toHex(decipheredText, bytesDecipheredSoFar), bytesDecipheredSoFar));

        // The comparision should ignore any padding that has been added and only consider the actual bytes written
        // by the cipher.
        assertThat(Arrays.copyOf(decipheredText, bytesDecipheredSoFar), is(inputData));

        // print out a string representation of the deciphered text to see if it results in our original data.
        System.out.println("decrypted output String" + new String(Arrays.copyOf(decipheredText, bytesDecipheredSoFar)));
    }

    /**
     *
     * TODO
     * - try out DES with a CBC mode - correct IV (√)
     * - try out DES with CBC mode - without providing a cipher - let's see what happens to the decrypted output
     * - try out DES with CBC mode - this time by providing an incorrect Iv - let's see what happens.
     * - review the basic operation of XOR
     */
}
