package org.v.db.service.configs;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.v.commons.config.CommonsPropertiesConfig;

@Getter
@Setter
@ConfigurationProperties(prefix = "properties")
public class DbServicePropertiesConfig extends CommonsPropertiesConfig {
    private String godUserUsername;
    private String globalAdminUserUsername;
    private String godUserEmail;
    private String globalAdminUserEmail;
    private String godUserPassword;
    private String globalAdminUserPassword;
}
