package org.example.config.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

    @Value("${security.authorities-claims}")
    private String authoritiesClaimName;

    //@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    //private String issuer;

    //@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    //private String jwkSetUri;

    //@Value("${spring.security.oauth2.resourceserver.jwt.jws-algorithms}")
    //private String jwsAlgorithm;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http
    ) throws Exception {
        /*http.oauth2ResourceServer(
          auth -> auth
              .opaqueToken(
                  opaqueTokenConfigurer -> opaqueTokenConfigurer
                      .introspectionUri("http://localhost:8090/token/introspect")
                          //TODO add credentials to secure introspect?
                      .introspectionClientCredentials("demo-client", "demo-secret")
                      .authenticationConverter(opaqueTokenAuthenticationConverter)
              )
        );*/
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt()
                //.decoder(jwtDecoder())
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
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

    /*JwtDecoder jwtDecoder() {
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withIssuer);
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.valueOf(jwsAlgorithm))
                .build();
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }*/

    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName(authoritiesClaimName);
        converter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }
}
