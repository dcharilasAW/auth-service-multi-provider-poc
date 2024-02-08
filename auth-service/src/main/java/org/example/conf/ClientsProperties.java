package org.example.conf;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.List;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Configuration
@ConfigurationProperties(prefix = "")
public class ClientsProperties {

    private List<Client> clients;

    public List<Client> getClients() {
        return clients;
    }

    public void setClients(List<Client> clients) {
        this.clients = clients;
    }

    public Client getClient(String name) {
        if (isNull(name)) {
            return null;
        }
        //TODO add exception handling if client not found
        return this.clients.stream().filter(c -> nonNull(c) && c.name.equals(name)).findFirst().get();
    }

    @Getter
    @Setter
    public static class Client {
        private String clientId;
        private String clientSecret;
        private String name;
        private String authorizeUrl;
        private String accessTokenUrl;
        private String scope;
        private String audience;
        private String redirectUri;
    }

}