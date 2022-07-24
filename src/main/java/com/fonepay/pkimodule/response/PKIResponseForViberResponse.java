package com.fonepay.pkimodule.response;

import lombok.Data;

@Data
public class PKIResponseForViberResponse {
    private String data;
    private String secretKey;
    private String signature;
}
