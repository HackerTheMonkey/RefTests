package org.techrefs.cryptography;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class CryptoUtilsTest {
    @Test
    public void toHex_should_return_hex_representation_of_binary_data() {
        System.out.println(CryptoUtils.toHex("Hello, CryptoWorld!".getBytes()));
    }

    @Test
    public void should_convert_a_hex_string_to_a_byte_array() {
        // Given
        String hexString16Octets = "AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E";
        // When
        byte[] converted = CryptoUtils.toByteArray(hexString16Octets);

        // Then
        assertThat(converted.length, is(16));

        assertThat(converted[0], is(new Byte((byte) 0xAE)));
        assertThat(converted[1], is(new Byte((byte) 0x68)));
        assertThat(converted[2], is(new Byte((byte) 0x52)));
        assertThat(converted[3], is(new Byte((byte) 0xF8)));
        assertThat(converted[4], is(new Byte((byte) 0x12)));
        assertThat(converted[5], is(new Byte((byte) 0x10)));
        assertThat(converted[6], is(new Byte((byte) 0x67)));
        assertThat(converted[7], is(new Byte((byte) 0xCC)));
        assertThat(converted[8], is(new Byte((byte) 0x4B)));
        assertThat(converted[9], is(new Byte((byte) 0xF7)));
        assertThat(converted[10], is(new Byte((byte) 0xA5)));
        assertThat(converted[11], is(new Byte((byte) 0x76)));
        assertThat(converted[12], is(new Byte((byte) 0x55)));
        assertThat(converted[13], is(new Byte((byte) 0x77)));
        assertThat(converted[14], is(new Byte((byte) 0xF3)));
        assertThat(converted[15], is(new Byte((byte) 0x9E)));
    }
}