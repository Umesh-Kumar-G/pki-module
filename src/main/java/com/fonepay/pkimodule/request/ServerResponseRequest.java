package com.fonepay.pkimodule.request;

import com.fonepay.pkimodule.response.ResponseFromServer;
import lombok.Data;

@Data
public class ServerResponseRequest {
    private ResponseFromServer responseFromServer;
    private String serverPublicKey;
    private String clientPrivateKey;
}
