package org.v.auth.service.configs;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
public class OAuth2AuthorizationRequestResolverConfig {
    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository repo) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(builder ->
                builder.additionalParameters(params -> {
                    ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
                    if (attrs == null) {
                        return;
                    }
                    HttpServletRequest request = attrs.getRequest();
                    if (!request.getRequestURI().startsWith("/oauth2/authorization/")) {
                        return;
                    }
                    String frontendRedirectUri = request.getParameter("frontend_redirect_uri");
                    if (frontendRedirectUri != null) {
                        request.getSession().setAttribute("FRONTEND_REDIRECT_URI", frontendRedirectUri);
                    }
                })
        );
        return resolver;
    }
}
