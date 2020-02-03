package com.idemia.cryptography.KeyStoreUtils;

import java.security.KeyStore;

import javax.crypto.SecretKey;

class KeyStoreUtils {


    private static final String keyStore_algorithm = "JCEKS";

    static KeyStore createKeyStore(String keyStorePassword, String alias, SecretKey secretKey, String secretKeyPassword) throws Exception{
        KeyStore keyStore = KeyStore.getInstance(keyStore_algorithm);
        keyStore.load(null,keyStorePassword.toCharArray());
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(secretKeyPassword.toCharArray());
        KeyStore.SecretKeyEntry privateKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(alias,privateKeyEntry,entryPassword);
        return keyStore;
    }
}
