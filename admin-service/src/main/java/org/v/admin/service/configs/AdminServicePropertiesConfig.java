package org.v.admin.service.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.v.commons.config.CommonsPropertiesConfig;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class AdminServicePropertiesConfig extends CommonsPropertiesConfig {
    private String unleashUrl;
    private String unleashApiToken;
}
