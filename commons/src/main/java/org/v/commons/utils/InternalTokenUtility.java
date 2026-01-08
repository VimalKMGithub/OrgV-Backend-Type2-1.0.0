package org.v.commons.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.v.commons.config.CommonsPropertiesConfig;
import org.v.commons.exceptions.UnauthorizedException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;

import static org.v.commons.enums.InternalTokenClaims.EXPIRATION;
import static org.v.commons.enums.InternalTokenClaims.REQUESTER_SERVICE_NAME;

@Component
public class InternalTokenUtility {
    @Value("${spring.application.name}")
    private String serviceName;
    private final SecretKey encryptionKey;

    public InternalTokenUtility(CommonsPropertiesConfig propertiesConfig) throws NoSuchAlgorithmException {
        this.encryptionKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256").digest(propertiesConfig.getInternalTokenEncryptionSecretKey().getBytes()),
                "AES"
        );
    }

    private Map<String, Object> defaultClaims() {
        return Map.of(
                REQUESTER_SERVICE_NAME.name(), serviceName,
                EXPIRATION.name(), Instant.now().plusSeconds(30).toEpochMilli()
        );
    }

    public String getToken() {
        return getToken(defaultClaims());
    }

    private String getToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .encryptWith(encryptionKey, Jwts.KEY.A256KW, Jwts.ENC.A256GCM)
                .compact();
    }

    private Claims parseEncryptedToken(String jwe) {
        return Jwts.parser()
                .decryptWith(encryptionKey)
                .build()
                .parseEncryptedClaims(jwe)
                .getPayload();
    }

    public String verifyInternalToken(String token) {
        Claims claims = parseEncryptedToken(token);
        if (claims.get(EXPIRATION.name(), Long.class) < Instant.now().toEpochMilli()) {
            throw new UnauthorizedException("Internal token has expired");
        }
        return claims.get(REQUESTER_SERVICE_NAME.name(), String.class);
    }
}
