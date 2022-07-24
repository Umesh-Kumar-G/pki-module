package com.fonepay.pkimodule.response;

import lombok.Data;

@Data
public class PKIResponseForRequest {
    private String signature;
    private String secretKey;
    private String data;
    private String clientKey;

    public PKIResponseForRequest(String signature, String secretKey, String data, String clientKey) {
        this.signature = signature;
        this.secretKey = secretKey;
        this.data = data;
        this.clientKey = clientKey;
    }
}
