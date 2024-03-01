package org.example.config.security;

import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    private TokenProperties props;

    Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        List<TokenProperties.Tenant> propsIssuers = props.getTenants();
        propsIssuers.forEach(tenant -> addManager(authenticationManagers, tenant));

        http.oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(authenticationManagerResolver())
        );

        http.cors(httpSecurityCorsConfigurer -> corsConfigurationSource())
                .authorizeHttpRequests(auth -> {
                            auth.requestMatchers(HttpMethod.OPTIONS).permitAll();//allow CORS option calls
                            auth.anyRequest().authenticated();
                        }
                );

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowCredentials(false);

        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Accept",
                "Cache-Control",
                "Content-Type",
                "Origin",
                "x-csrf-token",
                "x-requested-with"
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    public void addManager(Map<String, AuthenticationManager> authenticationManagers, TokenProperties.Tenant tenant) {
        //JwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(tenant.getIssuer());
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder(tenant));
        authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverterForKeycloak());
        authenticationManagers.put(tenant.getIssuer(), authenticationProvider::authenticate);
    }

    public JwtDecoder jwtDecoder(TokenProperties.Tenant tenant) {
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(tenant.getIssuer());
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withIssuer);
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withJwkSetUri(tenant.getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.valueOf(tenant.getJwsAlgorithm()))
                .build();
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }

    @Bean
    public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver() {
        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverterForKeycloak() {
        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = jwt -> {
            Map<String, Object> resourceAccess = jwt.getClaim("resource_access");

            Set<String> allRoles = new HashSet<>();
            resourceAccess.keySet().forEach(clientId -> {
                Object client = resourceAccess.get(clientId);
                LinkedTreeMap<String, List<String>> clientRoleMap = (LinkedTreeMap<String, List<String>>) client;
                List<String> clientRoles = new ArrayList<>(clientRoleMap.get("roles"));
                allRoles.addAll(clientRoles);
            });
            return allRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        };

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
