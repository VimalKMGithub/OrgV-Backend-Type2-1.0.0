package org.v.user.service.configs;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.v.commons.utils.UnleashServerUtility.createUnleashClient;

@Configuration
@RequiredArgsConstructor
public class UserServiceUnleashServerConfig {
    private final UserServicePropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return createUnleashClient(
                "user-service",
                "user-service-instance",
                propertiesConfig.getUnleashUrl(),
                propertiesConfig.getUnleashApiToken()
        );
    }
}
