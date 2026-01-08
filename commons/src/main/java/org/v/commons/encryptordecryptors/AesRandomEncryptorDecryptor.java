package org.v.commons.encryptordecryptors;

import org.springframework.stereotype.Component;
import org.v.commons.config.CommonsPropertiesConfig;
import org.v.commons.utils.AesRandomUtility;

import java.security.NoSuchAlgorithmException;

@Component
public class AesRandomEncryptorDecryptor {
    private final AesRandomUtility aesRandomUtility;

    public AesRandomEncryptorDecryptor(CommonsPropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.aesRandomUtility = new AesRandomUtility(propertiesConfig.getAesRandomSecretKey());
    }

    public String encrypt(String data) throws Exception {
        return aesRandomUtility.encrypt(data);
    }

    public String decrypt(String encryptedData) throws Exception {
        return aesRandomUtility.decrypt(encryptedData);
    }
}
