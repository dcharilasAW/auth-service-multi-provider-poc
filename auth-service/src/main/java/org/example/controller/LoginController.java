package org.example.controller;

import org.example.conf.ClientsProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static java.util.Objects.nonNull;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

@RestController
public class LoginController {

    private final ClientsProperties clientsProperties;

    public LoginController(ClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
    }

    @GetMapping(path = "/", produces = TEXT_PLAIN_VALUE)
    public String login(@RequestParam String clientName) {
        ClientsProperties.Client client = clientsProperties.getClient(clientName);
        return constructUrlWithParams(client);
    }

    private String constructUrlWithParams(ClientsProperties.Client client) {
        StringBuilder sb = new StringBuilder(client.getAuthorizeUrl());
        sb.append("?")
                .append("redirect_uri=" + client.getRedirectUri()).append("&")
                .append("scope=" + client.getScope()).append("&")
                .append("client_id=" + client.getClientId()).append("&")
                .append("response_type=code");

        if (nonNull(client.getAudience())) {
            sb.append("&").append("audience=" + client.getAudience());
        }

        return sb.toString();
    }
}
