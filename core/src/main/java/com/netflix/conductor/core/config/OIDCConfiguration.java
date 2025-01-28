/*
 *  Copyright 2025 Conductor authors
 *  <p>
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 *  the License. You may obtain a copy of the License at
 *  <p>
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  <p>
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 *  an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations under the License.
 */

package com.netflix.conductor.core.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(OIDCProperties.class)
public class OIDCConfiguration {
    private final OIDCProperties oidcProperties;
    ClientRegistrationRepository clientRegistrationRepository;
    public OIDCConfiguration(OIDCProperties oidcProperties) {
        this.oidcProperties = oidcProperties;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        if (oidcProperties.isEnabled()) {
            http.authorizeHttpRequests(expressionInterceptUrlRegistry -> {
                oidcProperties
                        .getRoles()
                        .forEach((key, value) ->
                                expressionInterceptUrlRegistry.requestMatchers(HttpMethod.valueOf(key)).hasAnyRole(value)
                        );
            })
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(Customizer.withDefaults())
            .oauth2Login(Customizer.withDefaults())
            .oauth2Client(Customizer.withDefaults())
            .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer -> {
                httpSecurityOAuth2ResourceServerConfigurer.jwt(jwtConfigurer -> {
                    jwtConfigurer.jwtAuthenticationConverter(
                            new RolesClaimConverter(
                                    new JwtGrantedAuthoritiesConverter()
                            )
                    );
                });
            });
        }
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(expressionInterceptUrlRegistry -> {
                    expressionInterceptUrlRegistry.anyRequest().permitAll();
                });
        return http.build();
    }

    @Bean
    @ConditionalOnProperty(name = "conductor.security.oidc.enabled", havingValue = "true")
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clients) {
        OAuth2AuthorizedClientService service =
                new InMemoryOAuth2AuthorizedClientService(clients);
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clients, service);
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();
        manager.setAuthorizedClientProvider(authorizedClientProvider);
        return manager;
    }

    @Bean
    @ConditionalOnProperty(name = "conductor.security.oidc.enabled", havingValue = "true")
    public WebClient webClientOAuth2(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction
                        (authorizedClientManager);
        oauth2.setDefaultClientRegistrationId(oidcProperties.getClientRegistrationId());
        return WebClient
                .builder()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(oidcProperties.getClientMaxInMemorySize()))
                .apply(oauth2.oauth2Configuration())
                .build();
    }

    @Bean
    @ConditionalOnProperty(name = "conductor.security.oidc.enabled", havingValue = "false", matchIfMissing = true)
    public WebClient webClient() {
        return WebClient
                .builder()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(oidcProperties.getClientMaxInMemorySize()))
                .build();
    }

    static class RolesClaimConverter implements Converter<Jwt, AbstractAuthenticationToken> {

        private static final String CLAIM_REALM_ACCESS = "realm_access";
        private static final String CLAIM_RESOURCE_ACCESS = "resource_access";
        private static final String CLAIM_ROLES = "roles";
        private final JwtGrantedAuthoritiesConverter wrappedConverter;

        public RolesClaimConverter(JwtGrantedAuthoritiesConverter conv) {
            wrappedConverter = conv;
        }

        @Override
        public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
            var grantedAuthorities = new ArrayList<>(wrappedConverter.convert(jwt));
            Map<String, Collection<String>> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);

            if (realmAccess != null && !realmAccess.isEmpty()) {
                Collection<String> roles = realmAccess.get(CLAIM_ROLES);
                if (roles != null && !roles.isEmpty()) {
                    Collection<GrantedAuthority> realmRoles = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    grantedAuthorities.addAll(realmRoles);
                }
            }
            Map<String, Map<String, Collection<String>>> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);

            if (resourceAccess != null && !resourceAccess.isEmpty()) {
                resourceAccess.forEach((resource, resourceClaims) -> {
                    resourceClaims.get(CLAIM_ROLES).forEach(
                            role -> grantedAuthorities.add(new SimpleGrantedAuthority(resource + "_" + role))
                    );
                });
            }
            return new JwtAuthenticationToken(jwt, grantedAuthorities);
        }
    }
}
