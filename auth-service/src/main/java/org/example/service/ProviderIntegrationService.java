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
        TokenResponse result = restTemplate.postForObject(client.getAccessTokenUrl(), request, TokenResponse.class);
        return result;
    }

    public TokenResponse refreshToken(String clientName, String token) {
        ClientsProperties.Client client = clientsProperties.getClient(clientName);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String,String> requestBody = new LinkedMultiValueMap();
        requestBody.put("grant_type", Collections.singletonList("refresh_token"));
        requestBody.put("refresh_token", Collections.singletonList(token));
        requestBody.put("client_id", Collections.singletonList(client.getClientId()));
        requestBody.put("client_secret", Collections.singletonList(client.getClientSecret()));

        HttpEntity<MultiValueMap<String,String>> request = new HttpEntity<>(requestBody, headers);

        RestTemplate restTemplate = new RestTemplate();
        TokenResponse result = restTemplate.postForObject(client.getAccessTokenUrl(), request, TokenResponse.class);
        return result;
    }

}
