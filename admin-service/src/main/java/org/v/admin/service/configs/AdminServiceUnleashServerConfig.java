package org.v.admin.service.configs;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.v.commons.utils.UnleashServerUtility.createUnleashClient;

@Configuration
@RequiredArgsConstructor
public class AdminServiceUnleashServerConfig {
    private final AdminServicePropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return createUnleashClient(
                "admin-service",
                "admin-service-instance",
                propertiesConfig.getUnleashUrl(),
                propertiesConfig.getUnleashApiToken()
        );
    }
}
