package com.pki.model;

import lombok.Data;

@Data
public class ServerResponseRequest {
    private ResponseFromServer responseFromServer;
    private String serverPublicKey;
    private String clientPrivateKey;
}
