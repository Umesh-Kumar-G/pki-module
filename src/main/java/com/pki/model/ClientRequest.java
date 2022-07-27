package com.pki.model;

import lombok.Data;

@Data
public class ClientRequest {
    private String data;
    private String clientKey;
    private String clientPrivateKey;
    private String serverEncryptionPublicKey;
}
