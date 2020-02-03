package com.idemia.cryptography.AsymmetricEncryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;

public class AsymmetricEncryptionUtil {

    private static final String RSA = "RSA";

    public static KeyPair generateRSAKeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(4096,secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    static byte[] performRSAEncryption(String PlainText, PrivateKey privateKey) throws Exception{
        Cipher cipher =  Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        return cipher.doFinal(PlainText.getBytes());
    }

    static String performRSADecryption(byte[] cipherText, PublicKey publicKey) throws Exception{
        Cipher cipher =  Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        return new String(cipher.doFinal(cipherText));
    }
}
