package org.v.commons.encryptordecryptors;

import org.springframework.stereotype.Component;
import org.v.commons.config.CommonsPropertiesConfig;
import org.v.commons.utils.AesStaticUtility;

import java.security.NoSuchAlgorithmException;

@Component
public class AesStaticEncryptorDecryptor {
    private final AesStaticUtility aesStaticUtility;

    public AesStaticEncryptorDecryptor(CommonsPropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.aesStaticUtility = new AesStaticUtility(propertiesConfig.getAesStaticSecretKey());
    }

    public String encrypt(String data) throws Exception {
        return aesStaticUtility.encrypt(data);
    }

    public String decrypt(String encryptedData) throws Exception {
        return aesStaticUtility.decrypt(encryptedData);
    }
}
