package org.techrefs.cryptography;

import org.junit.Test;
import org.techrefs.gson.cryptography.CryptoUtils;

public class CryptoUtilsTest {
    @Test
    public void toHex_should_return_hex_representation_of_binary_data(){
        System.out.println(CryptoUtils.toHex("Hello, CryptoWorld!".getBytes()));;
    }
}