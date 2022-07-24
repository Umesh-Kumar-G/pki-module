package com.fonepay.pkimodule.service.impl;

import com.fonepay.pkimodule.request.ClientRequest;
import com.fonepay.pkimodule.request.ServerResponseRequest;
import com.fonepay.pkimodule.response.PKIResponseForRequest;
import com.fonepay.pkimodule.service.PKIService;
import com.fonepay.pkimodule.util.EncryptionUtil;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Log4j2
public class PKIServiceImpl implements PKIService {

    @Value("${encrypt.algo}")
    private String ALGO;

    @Autowired
    EncryptionUtil encryptionUtil;


    @Override
    public PKIResponseForRequest processRequest(ClientRequest clientRequest) {
        try {
            Key key = generateKey();
            String data = encryptionUtil.encrypt(clientRequest.getData(), key);
            String signature = signUsingPrivateKey(data, clientRequest.getClientPrivateKey());
            String secretKey = encryptWithRSAPublicKey(clientRequest.getServerEncryptionPublicKey(), key.getEncoded());
            PKIResponseForRequest pkiResponseForRequest = new PKIResponseForRequest(signature, secretKey, data, clientRequest.getClientKey());
            return pkiResponseForRequest;
        } catch (Exception ex) {
            log.error("processRequest", ex);
            return null;
        }
    }

    @Override
    public Object processResponse(ServerResponseRequest serverResponseRequest) {
        try {
            boolean verified = verify(serverResponseRequest);
            if (!verified){
                return null;
            }
            Key secretKey = decryptWithPrivateKey(serverResponseRequest);
            String data = encryptionUtil.decrypt(serverResponseRequest.getResponseFromServer().getData(), secretKey);
            return data;
        } catch (Exception ex) {
            log.error("processResponse", ex);
            return null;
        }
    }

    private String encryptWithRSAPublicKey(String serverPublicKey , byte[] data) {
        try {
            PublicKey publicKey = generatePublicKeyFromString(serverPublicKey);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretKey = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(secretKey);
        } catch (Exception ex) {
            log.error("signWithRSAPrivateKey", ex);
            return null;
        }
    }

    private boolean verify(ServerResponseRequest serverResponseRequest) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        PublicKey publicKey = generatePublicKeyFromString(serverResponseRequest.getServerPublicKey());
        publicSignature.initVerify(publicKey);
        publicSignature.update(serverResponseRequest.getResponseFromServer().getData().getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = org.apache.tomcat.util.codec.binary.Base64.decodeBase64(serverResponseRequest.getResponseFromServer().getSignature());
        return publicSignature.verify(signatureBytes);
    }

    private Key generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private Key decryptWithPrivateKey(ServerResponseRequest serverResponseRequest) {
        try {
            PrivateKey privateKey = generatePrivateKeyFromString(serverResponseRequest.getClientPrivateKey());
            byte[] decodedKey = Base64.getDecoder().decode(serverResponseRequest.getResponseFromServer().getSecretKey());
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = cipher.doFinal(decodedKey);
            Key originalKey = new SecretKeySpec(decryptedKey, "AES");
            return originalKey;
        } catch (Exception ex) {
            return null;
        }
    }

    public static PrivateKey generatePrivateKeyFromString(String encodedPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decoder.decode(encodedPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(ks);
    }

    public static PublicKey generatePublicKeyFromString(String encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        X509EncodedKeySpec ks = new X509EncodedKeySpec(decoder.decode(encodedPublicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
    }

    public String signUsingPrivateKey(String plainText, String privateKeyString) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = generatePrivateKeyFromString(privateKeyString);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(signature);
    }
}
