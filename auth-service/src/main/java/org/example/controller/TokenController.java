package org.example.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.example.model.integration.TokenResponse;
import org.example.model.integration.TokenValidationRequest;
import org.example.service.ProviderIntegrationService;
import org.example.service.TokenValidationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class TokenController {

    private final static String AUTH_COOKIE_NAME = "auth-cookie";

    private ProviderIntegrationService service;
    private TokenValidationService tokenService;

    public TokenController(ProviderIntegrationService service, TokenValidationService tokenService) {
        this.service = service;
        this.tokenService = tokenService;
    }

    @PostMapping(path = "/token", produces = APPLICATION_JSON_VALUE)
    public TokenResponse getToken(HttpServletRequest request, @RequestParam String clientName) {
        return service.getAccessToken(clientName,getCodeFromCookie(request.getCookies()));
    }

    @PostMapping(path = "/token/refresh", produces = APPLICATION_JSON_VALUE)
    public TokenResponse refreshToken(HttpServletRequest request, @RequestParam String clientName) {
        return service.refreshToken(clientName,getCodeFromCookie(request.getCookies()));
    }

    private String getCodeFromCookie(Cookie[] cookies) {
        //TODO throw exception if cookie is not found
        return Arrays.asList(cookies).stream().filter(c -> AUTH_COOKIE_NAME.equals(c.getName())).findFirst().get().getValue();
    }

    @PostMapping(path = "/token/introspect", produces = APPLICATION_JSON_VALUE)
    public void introspectToken(@RequestBody TokenValidationRequest request,
                                @RequestHeader("Authorization") String token) {
        token = token.replace("Bearer ","");
        tokenService.validateToken(request, token);
    }
}
