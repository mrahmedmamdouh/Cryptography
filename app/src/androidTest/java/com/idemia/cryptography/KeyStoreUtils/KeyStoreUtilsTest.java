package com.idemia.cryptography.KeyStoreUtils;


import com.idemia.cryptography.SymmetricEncryption.SymmetricEncryptionUtil;

import org.junit.Test;

import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

public class KeyStoreUtilsTest {

    @Test
    public void createKeyStore() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtil.createAESKey();
        String secretKeyString = Arrays.toString(secretKey.getEncoded());
        KeyStore keyStore = KeyStoreUtils.createKeyStore("password","foo",secretKey,"keyPassword");
        assertNotNull(keyStore);

        keyStore.load(null,"password".toCharArray());
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection("keyPassword".toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("foo",protectionParameter);
        SecretKey secretKey1 = secretKeyEntry.getSecretKey();
        String secretKeyString1 = Arrays.toString(secretKey1.getEncoded());
        assertEquals(secretKeyString,secretKeyString1);
    }
}