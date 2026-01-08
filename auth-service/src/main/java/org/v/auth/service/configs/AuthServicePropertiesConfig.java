package org.v.auth.service.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.v.commons.config.CommonsPropertiesConfig;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class AuthServicePropertiesConfig extends CommonsPropertiesConfig {
    private String unleashUrl;
    private String unleashApiToken;
    private String accessTokenEncryptionSecretKey;
}
