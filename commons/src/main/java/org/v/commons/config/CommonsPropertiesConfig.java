package org.v.commons.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CommonsPropertiesConfig {
    private String aesRandomSecretKey;
    private String aesStaticSecretKey;
    private String internalTokenEncryptionSecretKey;
}
