package com.idemia.cryptography.Hash;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashUtils {

    private static final String SHA2 = "SHA-256";

    public static byte[] generateSHA2Salt() {
        byte [] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] SHADigestHash(String plainText, byte[] salt) throws Exception{
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(plainText.getBytes());
        byte[] valueToHash = byteArrayOutputStream.toByteArray();
        MessageDigest messageDigest = MessageDigest.getInstance(SHA2);
        return messageDigest.digest(valueToHash);
    }

    public static String hashPassword(String password){
        return BCrypt.hashpw(password,BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashPassword){
        return BCrypt.checkpw(password,hashPassword);
    }
}
