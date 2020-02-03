package com.idemia.cryptography.SymmetricEncryption;

import android.util.Log;


import org.junit.Test;

import java.util.Arrays;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

public class SymmetricEncryptionUtilTest {

    @Test
    public void createAESKey() throws Exception {
        SecretKey key = SymmetricEncryptionUtil.createAESKey();
        assertNotNull(key);
        Log.e("TAG", "createAESKey: " + Arrays.toString(key.getEncoded()));
    }

    @Test
    public void createEncryptionAES() throws Exception{
        SecretKey key = SymmetricEncryptionUtil.createAESKey();
        byte[] initializationVector = SymmetricEncryptionUtil.initializationVector();
        String PlainText = "This is the encrypted data for testing";
        byte [] encryptedResult = SymmetricEncryptionUtil.performAESEncryption(PlainText,key,initializationVector);
        String decryptedString = SymmetricEncryptionUtil.performAESDecryption(encryptedResult,key,initializationVector);
        Log.e("TAG", "createAESKey: " + decryptedString);

    }
}