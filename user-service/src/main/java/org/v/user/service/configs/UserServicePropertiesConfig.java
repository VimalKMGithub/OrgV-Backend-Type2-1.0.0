package org.v.user.service.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.v.commons.config.CommonsPropertiesConfig;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class UserServicePropertiesConfig extends CommonsPropertiesConfig {
    private String aesRandomSecretKey;
    private String aesStaticSecretKey;
    private String unleashUrl;
    private String unleashApiToken;
}
