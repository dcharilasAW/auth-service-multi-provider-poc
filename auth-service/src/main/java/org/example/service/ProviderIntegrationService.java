package org.example.service;

import org.example.conf.ClientsProperties;
import org.example.model.integration.TokenResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

import static java.util.Objects.nonNull;

@Service
public class ProviderIntegrationService {

    private final ClientsProperties clientsProperties;

    public ProviderIntegrationService(ClientsProperties clientsProperties) {
        this.clientsProperties = clientsProperties;
    }

    public TokenResponse getAccessToken(String clientName, String code) {
        ClientsProperties.Client client = clientsProperties.getClient(clientName);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String,String> requestBody = new LinkedMultiValueMap();
        requestBody.put("grant_type", Collections.singletonList("authorization_code"));
        requestBody.put("code", Collections.singletonList(code));
        requestBody.put("redirect_uri", Collections.singletonList(client.getRedirectUri()));
        requestBody.put("client_id", Collections.singletonList(client.getClientId()));
        requestBody.put("client_secret", Collections.singletonList(client.getClientSecret()));

        HttpEntity<MultiValueMap<String,String>> request = new HttpEntity<>(requestBody, headers);

        RestTemplate restTemplate = new RestTemplate();
        TokenResponse result = restTemplate.postForObject(constructUrlWithParams(client), request, TokenResponse.class);
        return result;
    }

    private String constructUrlWithParams(ClientsProperties.Client client) {
        StringBuilder sb = new StringBuilder(client.getAccessTokenUrl());
        sb.append("?").append("scope=" + client.getScope());

        if (nonNull(client.getAudience())) {
            sb.append("&").append("audience=" + client.getAudience());
        }

        return sb.toString();
    }
}
