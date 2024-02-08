package org.example.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.example.model.integration.TokenResponse;
import org.example.service.ProviderIntegrationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController("/token")
public class TokenController {

    private ProviderIntegrationService service;

    public TokenController(ProviderIntegrationService service) {
        this.service = service;
    }

    @PostMapping(path = "/", produces = APPLICATION_JSON_VALUE)
    public TokenResponse getToken(HttpServletRequest request) {
        //TODO read info from cookie
        request.getCookies();
        return service.getAccessToken("-","-");
    }
}
