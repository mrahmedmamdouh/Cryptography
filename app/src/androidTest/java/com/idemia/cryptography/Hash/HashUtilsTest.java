package com.idemia.cryptography.Hash;

import android.animation.TypeConverter;


import com.idemia.crypto_1.Hash.HashUtils;

import org.junit.Test;

import java.util.Arrays;
import java.util.UUID;

import static org.junit.Assert.*;

public class HashUtilsTest {

    @Test
    public void generateSHA2Salt() {
        byte[] salt = HashUtils.generateSHA2Salt();
        assertNotNull(salt);
    }

    @Test
    public void SHADigestHash() throws Exception{
        byte[] salt = HashUtils.generateSHA2Salt();
        String TextToHash = UUID.randomUUID().toString();
        byte[] textHashed = HashUtils.SHADigestHash(TextToHash,salt);
        assertNotNull(textHashed);
        byte[] textHashed2 = HashUtils.SHADigestHash(TextToHash,salt);
        assertEquals(Arrays.toString(textHashed), Arrays.toString(textHashed2));
    }

    @Test
    public void hashPassword() {
        String password = "123456abcdef";
        String hashPassword = HashUtils.hashPassword(password);
        boolean verification = HashUtils.verifyPassword(password,hashPassword);
        assertTrue(verification);
    }
}