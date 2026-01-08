package org.v.mail.service.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.v.commons.config.CommonsPropertiesConfig;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class MailServicePropertiesConfig extends CommonsPropertiesConfig {
    private String mailDisplayName;
    private String helpMailAddress;
}
