package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.example.conf.ClientsProperties;
import org.example.model.Token;
import org.example.model.integration.TokenValidationRequest;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.LinkedList;
import java.util.List;

@Service
public class TokenValidationService {

    private final ObjectMapper objectMapper;
    private final ClientsProperties clientsProperties;

    public TokenValidationService(ObjectMapper objectMapper, ClientsProperties clientsProperties) {
        this.objectMapper = objectMapper;
        this.clientsProperties = clientsProperties;
    }

    @SneakyThrows
    public void validateToken(TokenValidationRequest request, String accessToken) {
        //ClientsProperties.Client client = clientsProperties.getClient(request.getClientName());
        /*switch (client.getProvider()) {
            case AUTH0 -> validateAuth0Token(request,accessToken);
            case KEYCLOAK -> validateKeycloakToken(request,accessToken);
            //TODO custom exception
            default -> throw new Exception("Invalid provider");
        }*/

        verifyTokenNotRevoked(accessToken);
        /* Decode token */
        Token token = extractToken(accessToken);
        //verifyIssuer(token.getPayload());
        verifyTokenNotExpired(token.getPayload());
        verifyPermissions(token.getPayload(), request.getPermissions());
    }

    private Token extractToken(String token) {
        String[] parts = token.split("\\.");
        return Token.builder()
                .header(new JSONObject(decode(parts[0])))
                .payload(new JSONObject(decode(parts[1])))
                .signature(decode(parts[2]))
                .build();
    }

    private static String decode(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

    @SneakyThrows
    private void verifyTokenNotExpired(JSONObject payload) {
        if (payload.getLong("exp") <= (System.currentTimeMillis() / 1000)) {
            //TODO custom exception
            throw new Exception("Issuer validation failed");
        }
    }

    private void verifyUserNotBlacklisted() {
        //TODO check cache
    }

    private void verifyTokenNotRevoked(String accessToken) {
        //TODO check cache
    }

    private void verifySignature() {
        //TODO
    }

    @SneakyThrows
    private void verifyIssuer(JSONObject payload, ClientsProperties.Client client) {
        //TODO issuer
        if (!payload.get("iss").toString().contains("SOMETHING")) {
            //TODO custom exception
            throw new Exception("Issuer validation failed");
        }
    }

    @SneakyThrows
    private void verifyPermissions(JSONObject payload, List<String> requiredPermissions) {

        //TODO this field exists only in Auth0 tokens
        JSONArray jsonArray = payload.getJSONArray("permissions");
        List<String> tokenPermissions = new LinkedList<>();
        for (int i = 0, l = jsonArray.length(); i < l; i++) {
            tokenPermissions.add((String) jsonArray.get(i));
        }

        //TODO
        for (String permission: requiredPermissions) {
            if (!tokenPermissions.contains(permission)) {
                //TODO custom exception
                throw new Exception("Missing permission");
            }
        }
    }
}
