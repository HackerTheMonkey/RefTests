package org.techrefs.cryptography;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.InflaterInputStream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.techrefs.gson.cryptography.CryptoUtils.toByteArray;
import static org.techrefs.gson.cryptography.CryptoUtils.toHex;

public class AESCTRTestVectorsTest {


    @Test
    public void AES_with_CTR_mode_16BytePlainText_128BitKey() throws Exception {
        /**
         Test Vector #1: Encrypting 16 octets using AES-CTR with 128-bit key
         AES Key (128 bits)          : AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E
         AES-CTR IV (64 bits)        : 00 00 00 00 00 00 00 00
         Nonce      (32 bits)        : 00 00 00 30
         Plaintext String            : 'Single block msg'
         Plaintext                   : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
         Counter Block (128 bits)    : 00 00 00 30 00 00 00 00 00 00 00 00 00 00 00 01
         Key Stream    (1)           : B7 60 33 28 DB C2 93 1B 41 0E 16 C8 06 7E 62 DF
         Ciphertext                  : E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 00 00 30").
                withIv("00 00 00 00 00 00 00 00").
                withInitialCounter("00 00 00 00").
                withKeyBytes("AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E").
            build();

        byte[] cipherText = ctrCipher.encrypt("Single block msg".getBytes());

        assertThat(toHex(cipherText), is(toHex(toByteArray("E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8"))));

        ctrCipher.resetCounter();
        assertThat(new String(ctrCipher.encrypt(cipherText)), is("Single block msg"));
    }

    @Test
    public void AES_with_CTR_mode_32BytePlainText_128BitKey() throws Exception {
        /**
         *   Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
             AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
             AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
             Nonce            : 00 6C B6 DB
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
             Counter Block (1): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 01
             Key Stream    (1): 51 05 A3 05 12 8F 74 DE 71 04 4B E5 82 D7 DD 87
             Counter Block (2): 00 6C B6 DB C0 54 3B 59 DA 48 D9 0B 00 00 00 02
             Key Stream    (2): FB 3F 0C EF 52 CF 41 DF E4 FF 2A C4 8D 5C A0 37
             Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
                              : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 6C B6 DB").
                withIv("C0 54 3B 59 DA 48 D9 0B").
                withInitialCounter("00 00 00 00").
                withKeyBytes("7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63").
            build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");

        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88 EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(cipherText), is(plainText));
    }

    @Test
    public void AES_with_CTR_mode_36BytePlainText_128BitKey() throws Exception {
        /**
         *   Test Vector #3: Encrypting 36 octets using AES-CTR with 128-bit key
             AES Key          : 76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC
             AES-CTR IV       : 27 77 7F 3F  4A 17 86 F0
             Nonce            : 00 E0 01 7B
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                              : 20 21 22 23
             Counter Block (1): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 01
             Key Stream    (1): C1 CE 4A AB 9B 2A FB DE C7 4F 58 E2 E3 D6 7C D8
             Counter Block (2): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 02
             Key Stream    (2): 55 51 B6 38 CA 78 6E 21 CD 83 46 F1 B2 EE 0E 4C
             Counter Block (3): 00 E0 01 7B 27 77 7F 3F 4A 17 86 F0 00 00 00 03
             Key Stream    (3): 05 93 25 0C 17 55 36 00 A6 3D FE CF 56 23 87 E9
             Ciphertext       : C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7
                              : 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53
                              : 25 B2 07 2F
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 E0 01 7B").
                withIv("27 77 7F 3F 4A 17 86 F0").
                withInitialCounter("00 00 00 00").
                withKeyBytes("76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC").
                build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23");
        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53 25 B2 07 2F"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(plainText), is(cipherText));
    }

    @Test
    public void AES_with_CTR_mode_36BytePlainText_256BitKey() throws Exception {
        /**
         *   Test Vector #9: Encrypting 36 octets using AES-CTR with 256-bit key
             AES Key          : FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2
                              : AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D
             AES-CTR IV       : 51 A5 1D 70 A1 C1 11 48
             Nonce            : 00 1C C5 B7
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                              : 20 21 22 23
             Counter block (1): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 01
             Key stream    (1): EB 6D 50 81 19 0E BD F0 C6 7C 9E 4D 26 C7 41 A5
             Counter block (2): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 02
             Key stream    (2): A4 16 CD 95 71 7C EB 10 EC 95 DA AE 9F CB 19 00
             Counter block (3): 00 1C C5 B7 51 A5 1D 70 A1 C1 11 48 00 00 00 03
             Key stream    (3): 3E E1 C4 9B C6 B9 CA 21 3F 6E E2 71 D0 A9 33 39
             Ciphertext       : EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA
                              : B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F
                              : 1E C0 E6 B8
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 1C C5 B7").
                withIv("51 A5 1D 70 A1 C1 11 48").
                withInitialCounter("00 00 00 00").
                withKeyBytes("FF 7A 61 7C E6 91 48 E4 F1 72 6E 2F 43 58 1D E2 AA 62 D9 F8 05 53 2E DF F1 EE D6 87 FB 54 15 3D").
            build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23");

        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("EB 6C 52 82 1D 0B BB F7 CE 75 94 46 2A CA 4F AA B4 07 DF 86 65 69 FD 07 F4 8C C0 B5 83 D6 07 1F 1E C0 E6 B8"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(plainText), is(cipherText));
    }

    @Test
    public void AES_with_CTR_mode_16BytePlainText_192BitKey() throws Exception {
        /**
         *   Test Vector #4: Encrypting 16 octets using AES-CTR with 192-bit key
             AES Key          : 16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED
                              : 86 3D 06 CC FD B7 85 15
             AES-CTR IV       : 36 73 3C 14 7D 6D 93 CB
             Nonce            : 00 00 00 48
             Plaintext String : 'Single block msg'
             Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
             Counter Block (1): 00 00 00 48 36 73 3C 14 7D 6D 93 CB 00 00 00 01
             Key Stream    (1): 18 3C 56 28 8E 3C E9 AA 22 16 56 CB 23 A6 9A 4F
             Ciphertext       : 4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 00 00 48").
                withIv("36 73 3C 14 7D 6D 93 CB").
                withInitialCounter("00 00 00 00").
                withKeyBytes("16 AF 5B 14 5F C9 F5 79 C1 75 F9 3E 3B FB 0E ED 86 3D 06 CC FD B7 85 15").
            build();

        byte[] cipherText = ctrCipher.encrypt("Single block msg".getBytes());
        assertThat(toHex(cipherText), is(toHex(toByteArray("4B 55 38 4F E2 59 C9 C8 4E 79 35 A0 03 CB E9 28"))));

        ctrCipher.resetCounter();
        assertThat(new String(ctrCipher.encrypt(cipherText)), is("Single block msg"));
    }

    @Test
    public void AES_with_CTR_mode_32BytePlainText_192BitKey() throws Exception {
        /**
         *   Test Vector #5: Encrypting 32 octets using AES-CTR with 192-bit key
             AES Key          : 7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C
                              : 67 8C 3D B8 E6 F6 A9 1A
             AES-CTR IV       : 02 0C 6E AD C2 CB 50 0D
             Nonce            : 00 96 B0 3B
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
             Counter Block (1): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 01
             Key Stream    (1): 45 33 41 FF 64 9E 25 35 76 D6 A0 F1 7D 3C C3 90
             Counter Block (2): 00 96 B0 3B 02 0C 6E AD C2 CB 50 0D 00 00 00 02
             Key Stream    (2): 94 81 62 0F 4E C1 B1 8B E4 06 FA E4 5E E9 E5 1F
             Ciphertext       : 45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F
                              : 84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 96 B0 3B").
                withIv("02 0C 6E AD C2 CB 50 0D").
                withInitialCounter("00 00 00 00").
                withKeyBytes("7C 5C B2 40 1B 3D C3 3C 19 E7 34 08 19 E0 F6 9C 67 8C 3D B8 E6 F6 A9 1A").
            build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");

        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("45 32 43 FC 60 9B 23 32 7E DF AA FA 71 31 CD 9F 84 90 70 1C 5A D4 A7 9C FC 1F E0 FF 42 F4 FB 00"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(cipherText), is(plainText));
    }

    @Test
    public void AES_with_CTR_mode_36BytePlainText_192BitKey() throws Exception {
        /**
         *   Test Vector #6: Encrypting 36 octets using AES-CTR with 192-bit key
             AES Key          : 02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B
                              : F5 9B 60 A7 86 D3 E0 FE
             AES-CTR IV       : 5C BD 60 27 8D CC 09 12
             Nonce            : 00 07 BD FD
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
                              : 20 21 22 23
             Counter Block (1): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 01
             Key Stream    (1): 96 88 3D C6 5A 59 74 28 5C 02 77 DA D1 FA E9 57
             Counter Block (2): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 02
             Key Stream    (2): C2 99 AE 86 D2 84 73 9F 5D 2F D2 0A 7A 32 3F 97
             Counter Block (3): 00 07 BD FD 5C BD 60 27 8D CC 09 12 00 00 00 03
             Key Stream    (3): 8B CF 2B 16 39 99 B2 26 15 B4 9C D4 FE 57 39 98
             Ciphertext       : 96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58
                              : D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88
                              : AB EE 09 35
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 07 BD FD").
                withIv("5C BD 60 27 8D CC 09 12").
                withInitialCounter("00 00 00 00").
                withKeyBytes("02 BF 39 1E E8 EC B1 59 B9 59 61 7B 09 65 27 9B F5 9B 60 A7 86 D3 E0 FE").
            build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23");

        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("96 89 3F C5 5E 5C 72 2F 54 0B 7D D1 DD F7 E7 58 D2 88 BC 95 C6 91 65 88 45 36 C8 11 66 2F 21 88 AB EE 09 35"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(cipherText), is(plainText));
    }

    @Test
    public void AES_with_CTR_mode_16BytePlainText_256BitKey() throws Exception {
        /**
         *   Test Vector #7: Encrypting 16 octets using AES-CTR with 256-bit key
             AES Key          : 77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C
                              : 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04
             AES-CTR IV       : DB 56 72 C9 7A A8 F0 B2
             Nonce            : 00 00 00 60
             Plaintext String : 'Single block msg'
             Plaintext        : 53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67
             Counter Block (1): 00 00 00 60 DB 56 72 C9 7A A8 F0 B2 00 00 00 01
             Key Stream    (1): 47 33 BE 7A D3 E7 6E A5 3A 67 00 B7 51 8E 93 A7
             Ciphertext       : 14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 00 00 60").
                withIv("DB 56 72 C9 7A A8 F0 B2").
                withInitialCounter("00 00 00 00").
                withKeyBytes("77 6B EF F2 85 1D B0 6F 4C 8A 05 42 C8 69 6F 6C 6A 81 AF 1E EC 96 B4 D3 7F C1 D6 89 E6 C1 C1 04").
            build();

        byte[] cipherText = ctrCipher.encrypt("Single block msg".getBytes());

        assertThat(toHex(cipherText), is(toHex(toByteArray("14 5A D0 1D BF 82 4E C7 56 08 63 DC 71 E3 E0 C0"))));

        ctrCipher.resetCounter();
        assertThat(new String(ctrCipher.encrypt(cipherText)),is("Single block msg"));
    }

    @Test
    public void AES_with_CTR_mode_32BytePlainText_256BitKey() throws Exception {
        /**
         *   Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
             AES Key          : F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86
                              : C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84
             AES-CTR IV       : C1 58 5E F1 5A 43 D8 75
             Nonce            : 00 FA AC 24
             Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                              : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
             Counter block (1): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 01
             Key stream    (1): F0 5F 21 18 3C 91 67 2B 41 E7 0A 00 8C 43 BC A6
             Counter block (2): 00 FA AC 24 C1 58 5E F1 5A 43 D8 75 00 00 00 02
             Key stream    (2): A8 21 79 43 9B 96 8B 7D 4D 29 99 06 8F 59 B1 03
             Ciphertext       : F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9
                              : B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C
         */
        CTRCipher ctrCipher = new CTRCipher().
                withNonce("00 FA AC 24").
                withIv("C1 58 5E F1 5A 43 D8 75").
                withInitialCounter("00 00 00 00").
                withKeyBytes("F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86 C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84").
            build();

        byte[] plainText = toByteArray("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F");

        byte[] cipherText = ctrCipher.encrypt(plainText);

        assertThat(toHex(cipherText), is(toHex(toByteArray("F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9 B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C"))));

        ctrCipher.resetCounter();
        assertThat(ctrCipher.encrypt(cipherText),is(plainText));
    }

    @Test
    public void it() throws IOException {
        System.out.println(new String(toByteArray("30 32 37 37")));
        System.out.println(toByteArray("78 9c 55 50 51 4b c3 30 18 fc 2b 79 9c 20 e5 2e 69 da ce b7 cd 75 08 fa 20 73 15 f6 34 ea cc ec 58 c9 20 eb 10 fc 61 fe 01 ff 98 5f 32 b0 18 08 e1 2e 77 f7 5d d2 6c 1f ea d9 02 04 ac 31 86 39 2d b5 25 99 ab 71 11 d4 1a 72 53 5a 8b 45 ad 54 b3 5d 3f cd 36 62 32 15 56 f7 6b 0d b0 94 5d 81 c6 08 c0 74 d9 76 e1 d8 86 c1 49 ac 38 31 15 12 d5 67 77 18 da a3 0b 40 f1 47 9a 37 e7 c1 ab 55 4a 90 8f 97 f0 75 1e 82 db 1d 9d 8c 8c ba 98 28 17 82 ac 1c 45 04 78 76 e1 7c f2 13 e7 6f 60 04 12 79 14 e5 b1 25 cc 35 2d 99 e6 2e f4 07 af 26 73 88 30 a6 31 85 49 ad 0c cc 38 2d 2b 14 c9 6f 23 6f 89 8c 5a 98 72 64 ca cc e6 28 28 53 52 0f 8d 65 7f f9 e8 da bd f3 ea 65 d7 fd 7c 7b b7 77 3d 8a d4 f4 5f 88 ad 46 a6 92 10 a6 b7 d8 f8 1c 6d 5f db fe f0 ae 4e 5e 25 71 16 7b 2b 96 77 a2 4a 2d 61 d2 df d4 cd 4a b0 14 64 ca c9 79 5b e0 17 d2 ac 64 99").length);

        /**
         * Prepare out compressed data
         */
        byte[] compressedData = toByteArray("78 9c 55 50 51 4b c3 30 18 fc 2b 79 9c 20 e5 2e 69 da ce b7 cd 75 08 fa 20 73 15 f6 34 ea cc ec 58 c9 20 eb 10 fc 61 fe 01 ff 98 5f 32 b0 18 08 e1 2e 77 f7 5d d2 6c 1f ea d9 02 04 ac 31 86 39 2d b5 25 99 ab 71 11 d4 1a 72 53 5a 8b 45 ad 54 b3 5d 3f cd 36 62 32 15 56 f7 6b 0d b0 94 5d 81 c6 08 c0 74 d9 76 e1 d8 86 c1 49 ac 38 31 15 12 d5 67 77 18 da a3 0b 40 f1 47 9a 37 e7 c1 ab 55 4a 90 8f 97 f0 75 1e 82 db 1d 9d 8c 8c ba 98 28 17 82 ac 1c 45 04 78 76 e1 7c f2 13 e7 6f 60 04 12 79 14 e5 b1 25 cc 35 2d 99 e6 2e f4 07 af 26 73 88 30 a6 31 85 49 ad 0c cc 38 2d 2b 14 c9 6f 23 6f 89 8c 5a 98 72 64 ca cc e6 28 28 53 52 0f 8d 65 7f f9 e8 da bd f3 ea 65 d7 fd 7c 7b b7 77 3d 8a d4 f4 5f 88 ad 46 a6 92 10 a6 b7 d8 f8 1c 6d 5f db fe f0 ae 4e 5e 25 71 16 7b 2b 96 77 a2 4a 2d 61 d2 df d4 cd 4a b0 14 64 ca c9 79 5b e0 17 d2 ac 64 99");
        /**
         * Decompress it
         */
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
        InflaterInputStream inflaterInputStream = new InflaterInputStream(byteArrayInputStream);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i;
        while(( i = inflaterInputStream.read()) != -1){
            out.write(i);
        }
        inflaterInputStream.close();
        out.close();
        byteArrayInputStream.close();

        System.out.println(new String(out.toByteArray()));

        /**
         * Convert it into a UTF-8 String
         */
    }

}