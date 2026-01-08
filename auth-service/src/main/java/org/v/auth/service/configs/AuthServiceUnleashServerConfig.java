package org.v.auth.service.configs;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.v.commons.utils.UnleashServerUtility.createUnleashClient;

@Configuration
@RequiredArgsConstructor
public class AuthServiceUnleashServerConfig {
    private final AuthServicePropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return createUnleashClient(
                "auth-service",
                "auth-service-instance",
                propertiesConfig.getUnleashUrl(),
                propertiesConfig.getUnleashApiToken()
        );
    }
}
