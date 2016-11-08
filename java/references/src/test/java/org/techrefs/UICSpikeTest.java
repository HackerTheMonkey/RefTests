package org.techrefs;

import com.google.common.base.Charsets;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.zip.DeflaterInputStream;
import java.util.zip.InflaterInputStream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.techrefs.gson.cryptography.CryptoUtils.*;

/**
 * Original UIC protocol specs can be found here: https://goo.gl/MZNWAk
 */
public class UICSpikeTest {

    public static final int U_HEAD_FIXED_LENGTH = 53;
    public static final int U_HEAD_RECORD_LENGTH_LENGTH = 4;

    @Test
    public void encode() throws Exception {
        separator();
        System.out.println("ENCODING");
        separator();
        System.out.println("UIC Message Header");
        separator();


        StringBuilder uncompressedMessageBuilder = new StringBuilder();
        /**
         * Create the UIC Header. We don't really need padding here as all these match their expected length.
         */
        String uniqueMessageTypeId = "#UT";
        String messageTypeVersion = "01";
        String RICSCode = "3314";
        String signatureKeyId = "00001";

        /**
         * Create the UIC Message - UnCompressed
         */

        // U_HEAD record
        String headRecordId = padWithSpaces("U_HEAD", 6);
        String headRecordVersion = padWithSpaces("01", 2);
        String headRicsCode = padWithSpaces(RICSCode, 4);
        String ticketKey = padWithSpaces("151251114", 20);
        String editionTime = padWithSpaces("101220151755", 12);
        String flags = padWithSpaces("0", 1);
        String editionLanguage = padWithSpaces("DE", 2);
        String secondEditionLanguage = padWithSpaces("", 2);

        int headRecordLength = calculateLength(
                headRecordId,
                headRecordVersion,
                headRicsCode,
                editionTime,
                flags,
                editionLanguage,
                secondEditionLanguage,
                ticketKey
        );

        headRecordLength += U_HEAD_RECORD_LENGTH_LENGTH;
        assertThat(headRecordLength, is(U_HEAD_FIXED_LENGTH));

        // U_TLAY record
        String layoutRecordId = "U_TLAY";
        String layoutRecordVersion = "01";
        String layoutStandard = "RCT2";
        String numberOfFields = "0017"; //This should be a fixed number as we should know that beforehand as per the schema

        // U_TLAY fields, these don't need to be padded with anything.
        String ticketNameField = createField("00", "18", "01", "33", "2", "LONDONBRG");
        assertThat(ticketNameField.contains("0009LONDONBRG"), is(true));

        String surname = createField("00", "52", "01", "09", "0", "whitaker");
        assertThat(surname.contains("0008whitaker"), is(true));

        String firstname = createField("00", "62", "01", "09", "0", "ben");
        assertThat(firstname.contains("0003ben"), is(true));

        String productName = createField("01", "18", "01", "33", "1", "ManchesterP");
        assertThat(productName.contains("0011ManchesterP"), is(true));

        String numberOfCustomerGroup = createField("01", "52", "01", "02", "0", "1");
        assertThat(numberOfCustomerGroup.contains("00011"), is(true));

        String customerGroup = createField("01", "55", "01", "16", "0", "Person(en)");
        assertThat(customerGroup.contains("0010Person(en)"), is(true));

        String availableFromYear = createField("03", "01", "01", "04", "0", "2015");
        assertThat(availableFromYear.contains("00042015"), is(true));

        String tarrifZone = createField("03", "18", "01", "33", "0", "LONDON (B0)");
        assertThat(tarrifZone.contains("0011LONDON (B0)"), is(true));

        String dateOfBirth = createField("03", "52", "01", "10", "0", "05.01.1978");
        assertThat(dateOfBirth.contains("001005.01.1978"), is(true));

        String validFromDate = createField("06", "01", "01", "05", "0", "10.12");
        assertThat(validFromDate.contains("000510.12"), is(true));

        String validFromTime = createField("06", "07", "01", "05", "0", "17.54");
        assertThat(validFromTime.contains("000517.54"), is(true));

        String startStation = createField("06", "13", "01", "20", "0", "Manchester CentralST");
        assertThat(startStation.contains("0020Manchester CentralST"), is(true));

        String validUntilDate = createField("06", "52", "01", "05", "0", "10.12");
        assertThat(validUntilDate.contains("000510.12"), is(true));

        String validUntilTime = createField("06", "58", "01", "05", "0", "18.54");
        assertThat(validUntilTime.contains("000518.54"), is(true));

        String scopeText = createField("12", "01", "02", "50", "2", "Valid on 10.12.2015 17:54");
        assertThat(scopeText.contains("0025Valid on 10.12.2015 17:54"), is(true));

        String currency = createField("13", "52", "01", "03", "0", "GBP");
        assertThat(currency.contains("0003GBP"), is(true));

        String price = createField("13", "56", "01", "15", "0", "1,60");
        assertThat(price.contains("00041,60"), is(true));

        /**
         * Calculate the total length of the layout record then compare it against the value
         * that we already know about to make sure that we are doing things correctly.
         */
        int layoutRecordLength = calculateLength(
                layoutRecordId,
                layoutRecordVersion,
                layoutStandard,
                numberOfFields,
                "ABCD", // so that we take the record length field length into account.
                ticketNameField,
                surname,
                firstname,
                productName,
                numberOfCustomerGroup,
                customerGroup,
                availableFromYear,
                tarrifZone,
                dateOfBirth,
                validFromDate,
                validFromTime,
                startStation,
                validUntilDate,
                validUntilTime,
                scopeText,
                currency,
                price
        );
        assertThat(layoutRecordLength, is(380));

        // Create the message
        uncompressedMessageBuilder.
                // U_HEAD DATA
                        append(headRecordId).
                append(headRecordVersion).
                append(padWithZeros(String.valueOf(headRecordLength), U_HEAD_RECORD_LENGTH_LENGTH)).
                append(headRicsCode).
                append(ticketKey).
                append(editionTime).
                append(flags).
                append(editionLanguage).
                append(secondEditionLanguage).

                // U_TLAY DATA
                append(layoutRecordId).
                append(layoutRecordVersion).
                append(padWithZeros(String.valueOf(layoutRecordLength), 4)).
                append(layoutStandard).
                append(numberOfFields).
                append(ticketNameField).
                append(surname).
                append(firstname).
                append(productName).
                append(numberOfCustomerGroup).
                append(customerGroup).
                append(availableFromYear).
                append(tarrifZone).
                append(dateOfBirth).
                append(validFromDate).
                append(validFromTime).
                append(startStation).
                append(validUntilDate).
                append(validUntilTime).
                append(scopeText).
                append(currency).
                append(price);


        printField("uncompressedMessage(HEX)", toHex(uncompressedMessageBuilder.toString().getBytes(Charset.forName(Charsets.UTF_8.name()))));
        printField("uncompressedMessage(UTF-8 STRING)", uncompressedMessageBuilder.toString());
        /**
         * Compress The UIC Message
         */
        byte[] compressedMessage = deflate(uncompressedMessageBuilder.toString().getBytes(Charsets.UTF_8));

        byte[] dsaSignature = padWithNullBytes(computeDsaSignature(compressedMessage), 50);

        ByteArrayOutputStream uicMessage = new ByteArrayOutputStream();

        uicMessage.write(uniqueMessageTypeId.getBytes(Charsets.UTF_8));
        uicMessage.write(messageTypeVersion.getBytes(Charsets.UTF_8));
        uicMessage.write(RICSCode.getBytes(Charsets.UTF_8));
        uicMessage.write(signatureKeyId.getBytes(Charsets.UTF_8));
        uicMessage.write(dsaSignature);// must be padded with Null Bytes if less than 50 bytes
        uicMessage.write(padWithZeros(String.valueOf(compressedMessage.length), 4).getBytes(Charsets.UTF_8));
        uicMessage.write(compressedMessage);

        /**
         * Print out a Hex representation of the UIC message.
         */
        printField("UIC Message", "02 " + toHex(uicMessage.toByteArray()) + "03");
        decode(uicMessage.toByteArray());

    }

    private byte[] computeDsaSignature(byte[] compressedMessage) throws Exception {

        /**
         * Generate a new DSA keypair
         */
        KeyPairGenerator dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        secureRandom.setSeed(999);

        dsaKeyPairGenerator.initialize(1024, secureRandom);

        KeyPair dsaKeyPair = dsaKeyPairGenerator.generateKeyPair();

        /**
         * Print out the public key so that we can use it later to verify
         * the signature
         */
        printField("PublicKey", toHex(dsaKeyPair.getPublic().getEncoded()));

        /**
         * Sign the compressedMessage
         */
        Signature signer = Signature.getInstance("SHA1withDSA", "BC");
        signer.initSign(readDSAPrivateKey());
        signer.update(compressedMessage);

        return signer.sign();
    }

    private byte[] deflate(byte[] uncompressedMessage) throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(uncompressedMessage);
        DeflaterInputStream deflatorInputStream = new DeflaterInputStream(byteArrayInputStream);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        int i = 0;
        try {
            while ((i = deflatorInputStream.read()) != -1) {
                byteArrayOutputStream.write(i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            deflatorInputStream.close();
            byteArrayOutputStream.close();
            byteArrayInputStream.close();
        }

        return byteArrayOutputStream.toByteArray();
    }

    private String createField(String fieldLine, String fieldColumn, String fieldHeight, String fieldWidth, String fieldTextFormatting, String fieldText) {
        StringBuilder bucket = new StringBuilder();

        bucket.
                append(fieldLine).
                append(fieldColumn).
                append(fieldHeight).
                append(fieldWidth).
                append(fieldTextFormatting).
                append(padWithZeros(String.valueOf(fieldText.getBytes().length), 4)).
                append(fieldText);

        return bucket.toString();
    }

    private String padWithSpaces(String input, int length) {

        StringBuilder bucket = new StringBuilder();

        if (input.getBytes().length != length) {
            bucket.append(input);
            for (int i = 0; i < length - input.length(); i++) {
                bucket.append(SPACE);
            }
            assertThat(bucket.toString().length(), is(length));
            return bucket.toString();
        }

        return input;

    }

    private byte[] padWithNullBytes(byte[] input, int length) {
        if (input.length < length) {
            byte[] bytes = new byte[length];
            System.arraycopy(input, 0, bytes, 0, input.length);

            byte[] nullBytesPaddings = new byte[length - input.length];
            for (int i = 0; i < nullBytesPaddings.length; i++) {
                nullBytesPaddings[i] = 0;
            }

            System.arraycopy(nullBytesPaddings, 0, bytes, input.length, nullBytesPaddings.length);

            return bytes;
        }
        return input;
    }

    public PublicKey readDsaPublicKey() throws Exception{

        File file = new File("/Users/joseph/Downloads/Volumes/Bigdisk/Masabi/ns_reizigers_poc_public.pem");
        FileInputStream fileInputStream = new FileInputStream(file);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);
        byte[] publicKeyBytes = new byte[(int) file.length()];
        dataInputStream.readFully(publicKeyBytes);
        dataInputStream.close();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(publicKeyBytes));

        return certificate.getPublicKey();
    }

    public PrivateKey readDSAPrivateKey() throws Exception {
        /**
         * It seemed that the key that we have obtained from NS is not formatted
         * with PKCS8. That need to be converted into PKCS format by us in order
         * to be able to use it within BouncyCastle to sign stuff. Here is the OpenSSL
         * command that enabled us to convert the key
         *
         * openssl pkcs8 -inform PEM -in <your input file that's not a PKCS8> -topk8 -nocrypt -out <your output file> -outform PEM
         *
         * openssl pkcs8 -inform PEM -in ns_reizigers_poc.pem -topk8 -nocrypt -out ns_reizigers_poc_CONVERTED.pem -outform PEM
         *
         *
         * To read the private key components with OpenSSL
         *
         * openssl dsa -inform PEM -in ns_reizigers_poc.pem -text
         *
         */



        /**
         * read the contents of the pem file into a byte array
         */
        PemObject pemObject;
        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream("/Users/joseph/Downloads/Volumes/Bigdisk/Masabi/ns_reizigers_poc_CONVERTED.pem")));
        pemObject = pemReader.readPemObject();

        byte[] privateKeyBytes = pemObject.getContent();

        pemReader.close();

        /**
         * Generate our DSA private key
         */
        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA");

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        PrivateKey privateKey = dsaKeyFactory.generatePrivate(pkcs8EncodedKeySpec);

        return privateKey;
    }

    private String padWithZeros(String input, int length) {

        StringBuilder bucket = new StringBuilder();

        if (input.getBytes().length != length) {
            for (int i = 0; i < length - input.length(); i++) {
                bucket.append("0");
            }
            bucket.append(input);
            assertThat(bucket.toString().length(), is(length));
            return bucket.toString();
        }

        return input;

    }

    private int calculateLength(String... fields) {
        int sum = 0;
        for (String field : fields) {
            sum += field.getBytes().length;
        }
        return sum;
    }


    @Test
    public void verifyASignedMessage() throws Exception {

        /**
         * Construct a message to be signed!
         */
        String message = "The quick brown fox jumps over the lazy dog";

        /**
         * Read DSA private key from a file
         */
        PrivateKey dsaPrivateKey = readDSAPrivateKey();

        /**
         * Use the private key to sign a message
         */
        Signature signer = Signature.getInstance("SHA1withDSA", "BC");
        signer.initSign(dsaPrivateKey);
        signer.update(message.getBytes(Charsets.UTF_8));
        byte[] signedMessageBytes = signer.sign();

        /**
         * Read the DSA public key from a file.
         *
         * Worth noting that DSA public keys are stored on disk encoded in X509EncodedKeySpec
         *
         * more info @ http://goo.gl/eGBvm4
         */

        /**
         * Use the public key to verify the signature of the
         * given message. Here we have loaded the provided certificate as is and used it to obtain the
         * public key.
         */
        signer.initVerify(readDsaPublicKey());
        signer.update(message.getBytes(Charsets.UTF_8));
        boolean verificationOutcome = signer.verify(signedMessageBytes);

        assertThat(verificationOutcome, is(true));
    }

    @Test
    public void decode() throws IOException {

        String payload = "02 23 55 54 30 31 33 33 31 34 30 30 30 30 31 30 2c 02 14 1a d2 d3 72 51 c7 2b 54 4a 32 12 ac d6 23 7d f8 3a 91 83 38 02 14 0f 73 1a 80 46 05 0c 14 13 be 1e fc 25 c1 59 62 e6 e2 2f a8 00 00 00 00 30 32 37 37 78 9c 55 50 51 4b c3 30 18 fc 2b 79 9c 20 e5 2e 69 da ce b7 cd 75 08 fa 20 73 15 f6 34 ea cc ec 58 c9 20 eb 10 fc 61 fe 01 ff 98 5f 32 b0 18 08 e1 2e 77 f7 5d d2 6c 1f ea d9 02 04 ac 31 86 39 2d b5 25 99 ab 71 11 d4 1a 72 53 5a 8b 45 ad 54 b3 5d 3f cd 36 62 32 15 56 f7 6b 0d b0 94 5d 81 c6 08 c0 74 d9 76 e1 d8 86 c1 49 ac 38 31 15 12 d5 67 77 18 da a3 0b 40 f1 47 9a 37 e7 c1 ab 55 4a 90 8f 97 f0 75 1e 82 db 1d 9d 8c 8c ba 98 28 17 82 ac 1c 45 04 78 76 e1 7c f2 13 e7 6f 60 04 12 79 14 e5 b1 25 cc 35 2d 99 e6 2e f4 07 af 26 73 88 30 a6 31 85 49 ad 0c cc 38 2d 2b 14 c9 6f 23 6f 89 8c 5a 98 72 64 ca cc e6 28 28 53 52 0f 8d 65 7f f9 e8 da bd f3 ea 65 d7 fd 7c 7b b7 77 3d 8a d4 f4 5f 88 ad 46 a6 92 10 a6 b7 d8 f8 1c 6d 5f db fe f0 ae 4e 5e 25 71 16 7b 2b 96 77 a2 4a 2d 61 d2 df d4 cd 4a b0 14 64 ca c9 79 5b e0 17 d2 ac 64 99 03";

        System.out.println("");
        System.out.println("UIC Message Header");
        separator();
        /**
         * Convert the input HEX String payload into a binary array
         */
        byte[] originalPayload = toByteArray(payload);

        /**
         * Strip out the START_OF_TEXT and the END_OF_TEXT characters out of the input
         * message. These are encoded as per the UTF-8 character set.
         */
        byte[] rawInput = new byte[originalPayload.length - 2];
        System.arraycopy(originalPayload, 1, rawInput, 0, originalPayload.length - 2);

        assertThat(originalPayload[1], is(rawInput[0]));
        assertThat(originalPayload[originalPayload.length - 2], is(rawInput[rawInput.length - 1]));

        decode(rawInput);
    }

    private void decode(byte[] payload) throws IOException {

        separator();
        System.out.println("DECODING");
        separator();
        System.out.println("UIC Message Header");
        separator();
        /**
         * Convert the input HEX String payload into a binary array
         */
        byte[] rawInput = payload;

        int payloadPointer = 0;
        int fieldLength;
        /**
         * Unique Message type ID - 3 bytes
         */
        fieldLength = 3;
        printField("UniqueMessageTypeId", retrieveField(rawInput, payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Message Type Version - 2 bytes
         */
        fieldLength = 2;
        printField("MessageTypeVersion", retrieveField(rawInput, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * RICS Code of the RU that's signing - 4 bytes
         */
        fieldLength = 4;
        printField("RU_RICS_CODE", retrieveField(rawInput, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * ID of the signature key - 5 bytes
         */
        fieldLength = 5;
        printField("SignatureKeyID", retrieveField(rawInput, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * ID of the signature key - 5 bytes
         */
        fieldLength = 50;
        printField("DSA_Signature(Base64)", Base64.getEncoder().encodeToString(retrieveField(rawInput, +payloadPointer, fieldLength).getBytes()));
        payloadPointer += fieldLength;

        /**
         * Length of the compressed message - 4 bytes
         */
        fieldLength = 4;
        String compressedMessageLength = retrieveField(rawInput, +payloadPointer, fieldLength);
        printField("CompressedMessageLength", compressedMessageLength);
        payloadPointer += fieldLength;

        /**
         * Compressed message - as per the length computedCompressed message - as per the length computed above above
         */
        fieldLength = Integer.parseInt(compressedMessageLength);
        byte[] rawCompressedMessage = retrieveRawField(rawInput, +payloadPointer, fieldLength);
        printField("CompressedMessage(Base64)", Base64.getEncoder().encodeToString(rawCompressedMessage));

        assertThat(rawCompressedMessage.length, is(fieldLength));

        /**
         * INFLATE the compressed message using the DEFLATE algorithm
         */
        byte[] uncompressedMessage = inflate(rawCompressedMessage);
        System.out.println(new String(uncompressedMessage));
        printField("UncompressedMessageLength", String.valueOf(uncompressedMessage.length));

        /**
         * Now we can retrieve the various fields out of the uncompressed message.
         */
        System.out.println("");
        System.out.println("Uncompressed Message Records Sequence");

        separator();

        /**
         * Record ID - 6 bytes
         */
        payloadPointer = 0;
        fieldLength = 6;
        printField("RecordID", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Record Version - 2 bytes
         */
        fieldLength = 2;
        printField("RecordVersion", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Record Length - 4 bytes
         */
        fieldLength = 4;
        String recordLength = retrieveField(uncompressedMessage, +payloadPointer, fieldLength);
        printField("RecordLength", recordLength);
        payloadPointer += fieldLength;

        /**
         * RICS Code of the Distributing RU - 4 bytes
         */
        fieldLength = 4;
        printField("DistributingRuRICSCode", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Tickets Key - 20 bytes
         */
        fieldLength = 20;
        String value = retrieveField(uncompressedMessage, +payloadPointer, fieldLength);
        printField("TicketsKey", value);
        payloadPointer += fieldLength;

        /**
         * Edition Time - 12 bytes
         */
        fieldLength = 12;
        printField("EditionTime", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Flags - 1 byte
         */
        fieldLength = 1;
        printField("Flags", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Edition Language - 2 byte
         */
        fieldLength = 2;
        printField("EditionLanguage", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Second Edition Language - 2 byte
         */
        fieldLength = 2;
        printField("SecondEditionLanguage", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;
        int endOfUHeadRecord = payloadPointer;

        /**
         * Verify that the length of the U_HEAD record is what we have got within the record itself.
         */
        assertThat(Integer.parseInt(recordLength), is(payloadPointer));

        separator();
        /**
         * Record ID - 6 byte
         */
        fieldLength = 6;
        printField("RecordID", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;
        /**
         * Record Version - 2 byte
         */
        fieldLength = 2;
        printField("RecordVersion", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;
        /**
         * Record Length - 4 byte
         */
        fieldLength = 4;
        recordLength = retrieveField(uncompressedMessage, +payloadPointer, fieldLength);
        printField("RecordLength", recordLength);
        payloadPointer += fieldLength;
        /**
         * Verify that the length of the U_TLAY record is what we have got within the record itself.
         */
        assertThat(Integer.parseInt(recordLength), is(uncompressedMessage.length - endOfUHeadRecord));
        /**
         * Layout Standard - 4 byte
         */
        fieldLength = 4;
        printField("LayoutStandard", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        payloadPointer += fieldLength;

        /**
         * Number of Fields - 4 byte
         */
        fieldLength = 4;
        int numberOfFields = Integer.parseInt(retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
        printField("NumberOfFields", String.valueOf(numberOfFields));
        payloadPointer += fieldLength;


        /**
         * Now we print out the fields that we have for the U_TLAY record. These fields are what
         * they have sent us and what we call "The Schema"
         */

        for (int i = 0; i < numberOfFields; i++) {
            separator();
            System.out.println("Field " + (i + 1) + " - " + getFieldName(i));
            separator();
            /**
             * Field Line - 2 byte
             */
            fieldLength = 2;
            printField("FieldLine", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;
            /**
             * Field Column - 2 byte
             */
            fieldLength = 2;
            printField("FieldColumn", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;
            /**
             * Field Height - 2 byte
             */
            fieldLength = 2;
            printField("FieldHeight", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;
            /**
             * Field Width - 2 byte
             */
            fieldLength = 2;
            printField("FieldWidth", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;
            /**
             * Field Formatting - 1 byte
             */
            fieldLength = 1;
            printField("FieldFormatting", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;
            /**
             * Field Text Length - 4 byte
             */
            fieldLength = 4;
            String fieldTextLength = retrieveField(uncompressedMessage, +payloadPointer, fieldLength);
            printField("FieldTextLength", fieldTextLength);
            payloadPointer += fieldLength;
            /**
             * Field Text - as per the above value for FieldTextLength
             */
            fieldLength = Integer.parseInt(fieldTextLength);
            printField("FieldText", retrieveField(uncompressedMessage, +payloadPointer, fieldLength));
            payloadPointer += fieldLength;

            separator();
        }
    }

    private String getFieldName(int fieldNumber) {

        switch (++fieldNumber) {
            case 1:
                return "Ticket Name";
            case 2:
                return "Surname";
            case 3:
                return "Firstname";
            case 4:
                return "Product Name";
            case 5:
                return "Number of Customer Group";
            case 6:
                return "Customer Group";
            case 7:
                return "Available From Year";
            case 8:
                return "Tarrif Zone";
            case 9:
                return "Date of Birth";
            case 10:
                return "Valid From Date";
            case 11:
                return "Valid From Time";
            case 12:
                return "Start Station";
            case 13:
                return "Valid Until Date";
            case 14:
                return "Valid Until Time";
            case 15:
                return "Scope Text";
            case 16:
                return "Currency";
            case 17:
                return "Price";


        }
        return null;
    }

    private void separator() {
        System.out.println("----------------------------------------------------");
    }

    private byte[] inflate(byte[] input) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(input.length);

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(input);
        InflaterInputStream deflaterInputStream = new InflaterInputStream(byteArrayInputStream);

        int i;
        try {
            while ((i = deflaterInputStream.read()) != -1) {
                byteArrayOutputStream.write(i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            deflaterInputStream.close();
            byteArrayOutputStream.close();
            byteArrayInputStream.close();
        }

        return byteArrayOutputStream.toByteArray();
    }

    private String retrieveField(byte[] input, int startPosition, int length) {
        byte[] fieldRawData = new byte[length];
        System.arraycopy(input, startPosition, fieldRawData, 0, length);
        return new String(fieldRawData, Charset.forName("UTF-8"));
    }

    private byte[] retrieveRawField(byte[] input, int startPosition, int length) {
        byte[] fieldRawData = new byte[length];
        System.arraycopy(input, startPosition, fieldRawData, 0, length);
        return fieldRawData;
    }

    private void printField(String name, String value) {
        System.out.println(String.format("%s: %s", name, value));
    }

}