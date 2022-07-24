package com.fonepay.pkimodule.service;

import com.fonepay.pkimodule.request.ClientRequest;
import com.fonepay.pkimodule.request.ServerResponseRequest;
import com.fonepay.pkimodule.response.PKIResponseForRequest;
import com.fonepay.pkimodule.response.ResponseFromServer;

public interface PKIService {


    /**
     * to process request from client
     * @param clientRequest
     * @return
     */
    PKIResponseForRequest processRequest(ClientRequest clientRequest);

    /**
     * to process response from server
     * @param serverResponseRequest
     * @return
     */
    Object processResponse(ServerResponseRequest serverResponseRequest);

}
