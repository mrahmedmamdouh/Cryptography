package com.idemia.cryptography.DigitalSignature;

import com.idemia.cryptography.AsymmetricEncryption.AsymmetricEncryptionUtil;

import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.*;

public class DigitalSignatureUtilsTest {

    @Test
    public void generateDigitalSignature() throws Exception{
        String input = "this is the text needs to be signed and verified";
        KeyPair keyPair = AsymmetricEncryptionUtil.generateRSAKeyPair();
        byte[] signedInput = DigitalSignatureUtils.generateDigitalSignature(input.getBytes(),keyPair.getPrivate());
        assertNotNull(signedInput);
    }

    @Test
    public void verifyDigitalSignature() throws Exception {
        String input = "this is the text needs to be signed and verified";
        KeyPair keyPair = AsymmetricEncryptionUtil.generateRSAKeyPair();
        byte[] signedInput = DigitalSignatureUtils.generateDigitalSignature(input.getBytes(),keyPair.getPrivate());
        boolean verification = DigitalSignatureUtils.verifyDigitalSignature(input.getBytes(),signedInput,keyPair.getPublic());
        assertTrue(verification);
    }
}