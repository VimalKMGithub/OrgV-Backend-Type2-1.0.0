package org.v.gateway.service.configs;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.v.commons.utils.UnleashServerUtility.createUnleashClient;

@Configuration
@RequiredArgsConstructor
public class GatewayServiceUnleashServerConfig {
    private final GatewayServicePropertiesConfig propertiesConfig;

    @Bean
    public Unleash unleash() {
        return createUnleashClient(
                "gateway-service",
                "gateway-service-instance",
                propertiesConfig.getUnleashUrl(),
                propertiesConfig.getUnleashApiToken()
        );
    }
}
