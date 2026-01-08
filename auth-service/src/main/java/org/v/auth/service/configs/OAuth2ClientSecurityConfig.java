package org.v.auth.service.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.v.auth.service.handlers.OAuth2LoginSuccessHandler;
import org.v.commons.filters.InternalRequestFilter;

@Configuration
@RequiredArgsConstructor
public class OAuth2ClientSecurityConfig {
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final InternalRequestFilter internalRequestFilter;
    private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    @Bean
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) {
        http.csrf(AbstractHttpConfigurer::disable)
                .securityMatcher("/oauth2/**", "/login/oauth2/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(internalRequestFilter, SecurityContextHolderFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(auth -> auth.authorizationRequestResolver(authorizationRequestResolver))
                        .successHandler(oAuth2LoginSuccessHandler)
                );
        return http.build();
    }
}
