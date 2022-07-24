package com.fonepay.pkimodule.dummyController;

import com.fonepay.pkimodule.request.ClientRequest;
import com.fonepay.pkimodule.request.ServerResponseRequest;
import com.fonepay.pkimodule.response.PKIResponseForRequest;
import com.fonepay.pkimodule.service.PKIService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Provider;
import java.security.Security;
import java.util.TreeSet;

@RestController
@RequestMapping("pki")
public class DummyTestController {

    @Autowired
    PKIService pkiService;

    @PostMapping("/processClientRequest")
    public PKIResponseForRequest getPKIRequestFormat(@RequestBody ClientRequest clientRequest) {
        TreeSet<String> algorithms = new TreeSet<>();
        for (Provider provider : Security.getProviders())
            for (Provider.Service service: provider.getServices())
                if (service.getType().equals("Signature"))
                    algorithms.add(service.getAlgorithm());

        for (String algorithm: algorithms)
            System.out.println(algorithm);
        return pkiService.processRequest(clientRequest);
    }

    @PostMapping("/processServerResponse")
    public Object getPKIResponseFormatForServerResponse(@RequestBody ServerResponseRequest serverResponseRequest) {
        return pkiService.processResponse(serverResponseRequest);
    }
}
