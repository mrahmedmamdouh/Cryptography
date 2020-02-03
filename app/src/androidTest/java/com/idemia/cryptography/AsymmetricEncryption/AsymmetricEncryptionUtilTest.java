package com.idemia.cryptography.AsymmetricEncryption;

import android.util.Log;


import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static android.content.ContentValues.TAG;
import static org.junit.Assert.*;

public class AsymmetricEncryptionUtilTest {

    @Test
    public void generateRSAKeyPair() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtil.generateRSAKeyPair();
        Log.e(TAG, "Private Key: " + Arrays.toString(keyPair.getPrivate().getEncoded()));
        Log.e(TAG, "Public Key: " + Arrays.toString(keyPair.getPublic().getEncoded()));

    }

    @Test
    public void doEncryptionRoutine () throws Exception{
        KeyPair keyPair = AsymmetricEncryptionUtil.generateRSAKeyPair();
        String plainText = "This is the encrypted data for testing";
        byte [] encryptedText = AsymmetricEncryptionUtil.performRSAEncryption(plainText,keyPair.getPrivate());
        assertNotNull(encryptedText);
        String decryptedText = AsymmetricEncryptionUtil.performRSADecryption(encryptedText,keyPair.getPublic());
        assertNotNull(decryptedText);

    }
}