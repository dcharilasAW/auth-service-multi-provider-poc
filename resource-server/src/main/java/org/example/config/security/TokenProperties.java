package org.example.config.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "security")
class TokenProperties {
    private List<Tenant> tenants;

    public List<Tenant> getTenants() {
        return tenants;
    }

    public void setTenants(List<Tenant> tenants) {
        this.tenants = tenants;
    }

    public static class Tenant {
        private String issuer;
        private String jwsAlgorithm;
        private String jwkSetUri;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getJwsAlgorithm() {
            return jwsAlgorithm;
        }

        public void setJwsAlgorithm(String jwsAlgorithm) {
            this.jwsAlgorithm = jwsAlgorithm;
        }

        public String getJwkSetUri() {
            return jwkSetUri;
        }

        public void setJwkSetUri(String jwkSetUri) {
            this.jwkSetUri = jwkSetUri;
        }
    }
}