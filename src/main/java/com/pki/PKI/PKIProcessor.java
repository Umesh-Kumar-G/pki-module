package com.pki.PKI;

import com.pki.constant.KeyConstant;
import com.pki.model.ClientRequest;
import com.pki.model.ServerResponseRequest;
import com.pki.model.PKIResponseForRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PKIProcessor {

    public static PKIResponseForRequest processRequest(ClientRequest clientRequest) {
        try {
            Key key = generateKey();
            String data = encrypt(clientRequest.getData(), key);
            String signature = signUsingPrivateKey(data, clientRequest.getClientPrivateKey());
            String secretKey = encryptWithRSAPublicKey(clientRequest.getServerEncryptionPublicKey(), key.getEncoded());
            return new PKIResponseForRequest(signature, secretKey, data, clientRequest.getClientKey());
        } catch (Exception ex) {
            return null;
        }
    }

    public static String processResponse(ServerResponseRequest serverResponseRequest) {
        try {
            boolean verified = verify(serverResponseRequest);
            if (!verified) {
                return null;
            }
            Key secretKey = decryptWithPrivateKey(serverResponseRequest);
            return decrypt(serverResponseRequest.getResponseFromServer().getData(), secretKey);
        } catch (Exception ex) {
            return null;
        }
    }

    private static String encryptWithRSAPublicKey(String serverPublicKey, byte[] data) {
        try {
            PublicKey publicKey = generatePublicKeyFromString(serverPublicKey);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretKey = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(secretKey);
        } catch (Exception ex) {
            return null;
        }
    }

    private static boolean verify(ServerResponseRequest serverResponseRequest) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        PublicKey publicKey = generatePublicKeyFromString(serverResponseRequest.getServerPublicKey());
        publicSignature.initVerify(publicKey);
        publicSignature.update(serverResponseRequest.getResponseFromServer().getData().getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(serverResponseRequest.getResponseFromServer().getSignature());
        return publicSignature.verify(signatureBytes);
    }

    private static Key generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KeyConstant.KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static Key decryptWithPrivateKey(ServerResponseRequest serverResponseRequest) {
        try {
            PrivateKey privateKey = generatePrivateKeyFromString(serverResponseRequest.getClientPrivateKey());
            byte[] decodedKey = Base64.getDecoder().decode(serverResponseRequest.getResponseFromServer().getSecretKey());
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = cipher.doFinal(decodedKey);
            return new SecretKeySpec(decryptedKey, "AES");
        } catch (Exception ex) {
            return null;
        }
    }

    private static PrivateKey generatePrivateKeyFromString(String encodedPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decoder.decode(encodedPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);
    }

    private static PublicKey generatePublicKeyFromString(String encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        X509EncodedKeySpec ks = new X509EncodedKeySpec(decoder.decode(encodedPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
    }

    private static String signUsingPrivateKey(String plainText, String privateKeyString) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = generatePrivateKeyFromString(privateKeyString);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return org.apache.commons.codec.binary.Base64.encodeBase64String(signature);
    }

    private static String encrypt(String data, Key key) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = c.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encVal);
        } catch (Exception ex) {
            return null;
        }
    }

    private static String decrypt(String encryptedData, Key key) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedValue = c.doFinal(decodedValue);
            return new String(decryptedValue);
        } catch (Exception ex) {
            return null;
        }
    }
}
