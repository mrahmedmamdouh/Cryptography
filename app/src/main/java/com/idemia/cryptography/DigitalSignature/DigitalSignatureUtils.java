package com.idemia.cryptography.DigitalSignature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

class DigitalSignatureUtils {

    private static final String Signature_algorithm = "SHA256withRSA";

    static byte[] generateDigitalSignature(byte[] input, PrivateKey privateKey) throws Exception{
        Signature signature = Signature.getInstance(Signature_algorithm);
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    static boolean verifyDigitalSignature(byte[] input, byte[] inputSignature, PublicKey publicKey) throws Exception{
        Signature signature = Signature.getInstance(Signature_algorithm);
        signature.initVerify(publicKey);
        signature.update(input);
        return signature.verify(inputSignature);
    }
}
