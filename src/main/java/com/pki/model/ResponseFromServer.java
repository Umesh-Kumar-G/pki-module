package com.pki.model;

import lombok.Data;

@Data
public class ResponseFromServer {
    private String data;
    private String secretKey;
    private String signature;
}
