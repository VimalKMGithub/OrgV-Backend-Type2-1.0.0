package org.v.auth.service.utils;

import io.getunleash.Unleash;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;
import org.springframework.stereotype.Component;
import org.v.auth.service.configs.AuthServicePropertiesConfig;
import org.v.auth.service.services.AuthServiceMailService;
import org.v.commons.clients.DbServiceClient;
import org.v.commons.dtos.AuthenticationDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.enums.MfaType;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.exceptions.UnauthorizedException;
import org.v.commons.models.ExternalIdentityModel;
import org.v.commons.models.PermissionModel;
import org.v.commons.models.RoleModel;
import org.v.commons.models.UserModel;
import ua_parser.Client;
import ua_parser.Parser;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.v.auth.service.enums.AccessTokenClaims.*;
import static org.v.commons.constants.HeadersCookies.*;
import static org.v.commons.enums.FeatureFlags.EMAIL_CONFIRMATION_ON_NEW_SIGN_IN;
import static org.v.commons.enums.FeatureFlags.EMAIL_CONFIRMATION_ON_SUSPICIOUS_ACTIVITY;
import static org.v.commons.enums.MailType.NEW_SIGN_IN_CONFIRMATION;
import static org.v.commons.enums.MailType.SUSPICIOUS_ACTIVITY_CONFIRMATION;
import static org.v.commons.utils.RedisServiceUtility.*;

@Component
public class AccessTokenUtility {
    public static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(15);
    private static final long ACCESS_TOKEN_EXPIRES_IN_MILLI_SECONDS = ACCESS_TOKEN_EXPIRES_IN_SECONDS * 1000;
    public static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final Duration ACCESS_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    private static final Duration REFRESH_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);
    private static final Parser USER_AGENT_PARSER = new Parser();
    private static final String ACCESS_TOKEN_ID_PREFIX = "auth-service-access-token-id:";
    private static final String USER_DEVICE_IDS_PREFIX = "auth-service-user-device-ids:";
    private static final String USER_DEVICES_STATS_PREFIX = "auth-service-user-devices-stats:";
    private static final String REFRESH_TOKEN_PREFIX = "auth-service-refresh-token:";
    private static final String REFRESH_TOKEN_USER_ID_MAPPING_PREFIX = "auth-service-refresh-token-user-id-mapping:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "auth-service-refresh-token-mapping:";
    private final SecretKey encryptionKey;
    private final DbServiceClient dbServiceClient;
    private final Unleash unleash;
    private final StringRedisTemplate stringRedisTemplate;
    private final AuthServiceMailService mailService;
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;

    public AccessTokenUtility(AuthServicePropertiesConfig propertiesConfig,
                              DbServiceClient dbServiceClient,
                              Unleash unleash,
                              StringRedisTemplate stringRedisTemplate,
                              AuthServiceMailService mailService,
                              AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor,
                              AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor) throws NoSuchAlgorithmException {
        this.encryptionKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256").digest(propertiesConfig.getAccessTokenEncryptionSecretKey().getBytes()),
                "AES"
        );
        this.dbServiceClient = dbServiceClient;
        this.unleash = unleash;
        this.stringRedisTemplate = stringRedisTemplate;
        this.mailService = mailService;
        this.aesStaticEncryptorDecryptor = aesStaticEncryptorDecryptor;
        this.aesRandomEncryptorDecryptor = aesRandomEncryptorDecryptor;
    }

    private String generateAccessTokenId(UserModel user,
                                         HttpServletRequest request) throws Exception {
        String accessTokenId = UUID.randomUUID().toString();
        redisSave(
                getEncryptedAccessTokenIdKey(user, request),
                aesRandomEncryptorDecryptor.encrypt(accessTokenId),
                ACCESS_TOKEN_EXPIRES_IN_DURATION,
                stringRedisTemplate
        );
        return accessTokenId;
    }

    private String getEncryptedAccessTokenIdKey(UserModel user,
                                                HttpServletRequest request) throws Exception {
        return getEncryptedAccessTokenIdKey(user.getId(), request);
    }

    private String getEncryptedAccessTokenIdKey(UUID userId,
                                                HttpServletRequest request) throws Exception {
        return getEncryptedAccessTokenIdKey(userId, request.getHeader(X_DEVICE_ID_HEADER));
    }

    private String getEncryptedAccessTokenIdKey(UUID userId,
                                                String deviceId) throws Exception {
        return getEncryptedAccessTokenIdKey(userId.toString(), deviceId);
    }

    private String getEncryptedAccessTokenIdKey(String userId,
                                                String deviceId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(ACCESS_TOKEN_ID_PREFIX + userId + ":" + deviceId);
    }

    private Map<String, Object> buildTokenClaims(UserModel user,
                                                 HttpServletRequest request,
                                                 Client client) throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put(DEVICE.name(), client.device.family);
        claims.put(OS.name(), client.os.family);
        claims.put(AGENT.name(), client.userAgent.family);
        claims.put(ACCESS_TOKEN_ID.name(), generateAccessTokenId(user, request));
        claims.put(DEVICE_ID.name(), request.getHeader(X_DEVICE_ID_HEADER));
        claims.put(USER_ID.name(), user.getId().toString());
        claims.put(USERNAME.name(), user.getUsername());
        claims.put(EMAIL.name(), user.getEmail());
        claims.put(REAL_EMAIL.name(), user.getRealEmail());
        Set<String> authorities = new HashSet<>();
        for (RoleModel role : user.getRoles()) {
            authorities.add(role.getRoleName());
            for (PermissionModel permission : role.getPermissions()) {
                authorities.add(permission.getPermissionName());
            }
        }
        claims.put(AUTHORITIES.name(), String.join(",", authorities));
        claims.put(MFA_ENABLED.name(), user.isMfaEnabled());
        Set<String> mfaMethods = new HashSet<>();
        for (MfaType mfaType : user.getMfaMethods()) {
            mfaMethods.add(mfaType.name());
        }
        claims.put(MFA_METHODS.name(), String.join(",", mfaMethods));
        claims.put(EXPIRATION.name(), Instant.now().toEpochMilli() + ACCESS_TOKEN_EXPIRES_IN_MILLI_SECONDS);
        Set<String> emailsFromExternalIdentities = new HashSet<>();
        if (user.getExternalIdentities() != null) {
            for (ExternalIdentityModel externalIdentity : user.getExternalIdentities()) {
                emailsFromExternalIdentities.add(externalIdentity.getEmail());
            }
        }
        claims.put(EMAILS_FROM_EXTERNAL_IDENTITIES.name(), String.join(",", emailsFromExternalIdentities));
        return claims;
    }

    private String generateRefreshToken(UserModel user,
                                        HttpServletRequest request) throws Exception {
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user, request);
        String existingEncryptedRefreshToken = redisGet(encryptedRefreshTokenKey, stringRedisTemplate);
        if (existingEncryptedRefreshToken != null) {
            String oldRefreshToken = aesRandomEncryptorDecryptor.decrypt(existingEncryptedRefreshToken);
            redisDeleteAll(
                    Set.of(
                            encryptedRefreshTokenKey,
                            getEncryptedRefreshTokenMappingKey(oldRefreshToken),
                            getEncryptedRefreshTokenUserIdMappingKey(oldRefreshToken)
                    )
                    , stringRedisTemplate
            );
        }
        String refreshToken = UUID.randomUUID().toString();
        String encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKey(refreshToken);
        String encryptedRefreshTokenUserIdMappingKey = getEncryptedRefreshTokenUserIdMappingKey(refreshToken);
        try {
            redisSave(
                    encryptedRefreshTokenKey,
                    aesRandomEncryptorDecryptor.encrypt(refreshToken),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION,
                    stringRedisTemplate
            );
            redisSave(
                    encryptedRefreshTokenMappingKey,
                    aesRandomEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER)),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION,
                    stringRedisTemplate
            );
            redisSave(
                    encryptedRefreshTokenUserIdMappingKey,
                    aesRandomEncryptorDecryptor.encrypt(user.getId().toString()),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION,
                    stringRedisTemplate
            );
            return refreshToken;
        } catch (Exception ex) {
            redisDeleteAll(
                    Set.of(
                            encryptedRefreshTokenKey,
                            encryptedRefreshTokenMappingKey,
                            encryptedRefreshTokenUserIdMappingKey
                    ),
                    stringRedisTemplate
            );
            throw new RuntimeException("Failed to generate refresh token", ex);
        }
    }

    private String getEncryptedRefreshTokenKey(UserModel user,
                                               HttpServletRequest request) throws Exception {
        return getEncryptedRefreshTokenKey(user.getId(), request);
    }

    private String getEncryptedRefreshTokenKey(UUID userId,
                                               HttpServletRequest request) throws Exception {
        return getEncryptedRefreshTokenKey(userId, request.getHeader(X_DEVICE_ID_HEADER));
    }

    private String getEncryptedRefreshTokenKey(UUID userId,
                                               String deviceId) throws Exception {
        return getEncryptedRefreshTokenKey(userId.toString(), deviceId);
    }

    private String getEncryptedRefreshTokenKey(String userId,
                                               String deviceId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_PREFIX + userId + ":" + deviceId);
    }

    private String getEncryptedRefreshTokenMappingKey(String refreshToken) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
    }

    private String getEncryptedRefreshTokenUserIdMappingKey(String refreshToken) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_USER_ID_MAPPING_PREFIX + refreshToken);
    }

    private String encryptToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .encryptWith(encryptionKey, Jwts.KEY.A256KW, Jwts.ENC.A256GCM)
                .compact();
    }

    private Map<String, Object> generateAccessToken(UserModel user,
                                                    HttpServletRequest request,
                                                    String encryptedDeviceId,
                                                    String encryptedDeviceStatsKey,
                                                    Client client) throws Exception {
        String encryptedDeviceIdsKey = getEncryptedDeviceIdsKey(user);
        long now = Instant.now().toEpochMilli();
        Boolean newSignIn = redisAddZSetMember(
                encryptedDeviceIdsKey,
                encryptedDeviceId,
                now,
                REFRESH_TOKEN_EXPIRES_IN_DURATION,
                stringRedisTemplate
        );
        sendEmailConfirmationOnNewSignIn(newSignIn, user);
        addDeviceStats(
                encryptedDeviceId,
                encryptedDeviceStatsKey,
                request,
                client,
                now
        );
        Long zSetSize = redisGetZSetSize(encryptedDeviceIdsKey, stringRedisTemplate);
        if (zSetSize != null && zSetSize > user.getAllowedConcurrentLogins()) {
            removeOldLogins(
                    redisPopNMinZSetMembers(
                            encryptedDeviceIdsKey,
                            zSetSize - user.getAllowedConcurrentLogins(),
                            stringRedisTemplate
                    ),
                    user,
                    encryptedDeviceStatsKey
            );
        }
        Map<String, Object> accessToken = new HashMap<>();
        accessToken.put("access_token", encryptToken(buildTokenClaims(user, request, client)));
        accessToken.put("expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS);
        accessToken.put("token_type", "Bearer");
        return accessToken;
    }

    private String getEncryptedDeviceIdsKey(UserModel user) throws Exception {
        return getEncryptedDeviceIdsKey(user.getId());
    }

    private String getEncryptedDeviceIdsKey(UUID userId) throws Exception {
        return getEncryptedDeviceIdsKey(userId.toString());
    }

    private String getEncryptedDeviceIdsKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(USER_DEVICE_IDS_PREFIX + userId);
    }

    private void sendEmailConfirmationOnNewSignIn(Boolean newSignIn,
                                                  UserModel user) throws Exception {
        if (newSignIn != null && newSignIn && unleash.isEnabled(EMAIL_CONFIRMATION_ON_NEW_SIGN_IN.name())) {
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "New Sign In Detected",
                    "",
                    NEW_SIGN_IN_CONFIRMATION
            );
        }
    }

    private void addDeviceStats(String encryptedDeviceId,
                                String encryptedDeviceStatsKey,
                                HttpServletRequest request,
                                Client client,
                                long now) throws Exception {
        StringBuilder deviceInfo = new StringBuilder();
        deviceInfo.append(client.device.family).append(";").append(client.os.family);
        if (client.os.major != null) {
            deviceInfo.append(" ").append(client.os.major);
            if (client.os.minor != null) {
                deviceInfo.append(".").append(client.os.minor);
                if (client.os.patch != null) {
                    deviceInfo.append(".").append(client.os.patch);
                }
            }
        }
        deviceInfo.append(";").append(client.userAgent.family);
        if (client.userAgent.major != null) {
            deviceInfo.append(" ").append(client.userAgent.major);
            if (client.userAgent.minor != null) {
                deviceInfo.append(".").append(client.userAgent.minor);
                if (client.userAgent.patch != null) {
                    deviceInfo.append(".").append(client.userAgent.patch);
                }
            }
        }
        String ipAddress = request.getHeader(X_FORWARDER_FOR_HEADER);
        if (ipAddress == null || ipAddress.isBlank()) {
            ipAddress = request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
        }
        deviceInfo.append(";").append(ipAddress);
        deviceInfo.append(";").append(now);
        redisAddHashMember(
                encryptedDeviceStatsKey,
                encryptedDeviceId,
                aesRandomEncryptorDecryptor.encrypt(deviceInfo.toString()),
                REFRESH_TOKEN_EXPIRES_IN_DURATION,
                stringRedisTemplate
        );
    }

    private void removeOldLogins(Set<ZSetOperations.TypedTuple<String>> oldLogins,
                                 UserModel user,
                                 String encryptedDeviceStatsKey) throws Exception {
        if (oldLogins != null && !oldLogins.isEmpty()) {
            Set<String> keysToDelete = new HashSet<>();
            Object[] membersToRemove = new Object[oldLogins.size()];
            int index = 0;
            String tempStr;
            for (ZSetOperations.TypedTuple<String> oldLogin : oldLogins) {
                if (oldLogin.getValue() != null) {
                    membersToRemove[index++] = oldLogin.getValue();
                    tempStr = aesStaticEncryptorDecryptor.decrypt(oldLogin.getValue());
                    keysToDelete.add(getEncryptedAccessTokenIdKey(user.getId(), tempStr));
                    tempStr = getEncryptedRefreshTokenKey(user.getId(), tempStr);
                    keysToDelete.add(tempStr);
                    tempStr = redisGet(tempStr, stringRedisTemplate);
                    if (tempStr != null) {
                        tempStr = aesRandomEncryptorDecryptor.decrypt(tempStr);
                        keysToDelete.add(getEncryptedRefreshTokenMappingKey(tempStr));
                        keysToDelete.add(getEncryptedRefreshTokenUserIdMappingKey(tempStr));
                    }
                }
            }
            if (!keysToDelete.isEmpty()) {
                redisDeleteAll(keysToDelete, stringRedisTemplate);
                redisRemoveHashMembers(
                        encryptedDeviceStatsKey,
                        membersToRemove,
                        stringRedisTemplate
                );
            }
        }
    }

    public Map<String, Object> generateTokens(UserModel user,
                                              HttpServletRequest request) throws Exception {
        checkDeviceId(request);
        Map<String, Object> tokens = generateAccessToken(
                user,
                request,
                aesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER)),
                getEncryptedDeviceStatsKey(user),
                USER_AGENT_PARSER.parse(request.getHeader(USER_AGENT_HEADER))
        );
        tokens.put("refresh_token", generateRefreshToken(user, request));
        user.recordSuccessfulLogin();
        dbServiceClient.updateUser(user);
        return tokens;
    }

    private void checkDeviceId(HttpServletRequest request) {
        if (request.getHeader(X_DEVICE_ID_HEADER) == null || request.getHeader(X_DEVICE_ID_HEADER).isBlank()) {
            throw new SimpleBadRequestException("X-Device-ID header is required");
        }
    }

    public String getEncryptedDeviceStatsKey(UserModel user) throws Exception {
        return getEncryptedDeviceStatsKey(user.getId());
    }

    private String getEncryptedDeviceStatsKey(UUID userId) throws Exception {
        return getEncryptedDeviceStatsKey(userId.toString());
    }

    private String getEncryptedDeviceStatsKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(USER_DEVICES_STATS_PREFIX + userId);
    }

    private Claims parseEncryptedToken(String jwe) {
        return Jwts.parser()
                .decryptWith(encryptionKey)
                .build()
                .parseEncryptedClaims(jwe)
                .getPayload();
    }

    public AuthenticationDto verifyAccessToken(String accessToken,
                                               HttpServletRequest request) throws Exception {
        Claims claims = parseEncryptedToken(accessToken);
        if (claims.get(EXPIRATION.name(), Long.class) < Instant.now().toEpochMilli()) {
            throw new UnauthorizedException("Token expired");
        }
        String userId = claims.get(USER_ID.name(), String.class);
        String deviceId = claims.get(DEVICE_ID.name(), String.class);
        if (!deviceId.equals(request.getHeader(X_DEVICE_ID_HEADER))) {
            redisDelete(getEncryptedAccessTokenIdKey(userId, deviceId), stringRedisTemplate);
            sendEmailConfirmationOnSuspiciousActivity(
                    aesStaticEncryptorDecryptor.decrypt(claims.get(EMAIL.name(), String.class)),
                    "Access token used from different device. Access token breach detected"
            );
            throw new UnauthorizedException("Invalid token");
        }
        String encryptedAccessTokenIdKey = getEncryptedAccessTokenIdKey(userId, deviceId);
        String encryptedAccessTokenId = redisGet(encryptedAccessTokenIdKey, stringRedisTemplate);
        if (encryptedAccessTokenId == null ||
                !aesRandomEncryptorDecryptor.decrypt(encryptedAccessTokenId).equals(claims.get(ACCESS_TOKEN_ID.name(), String.class))) {
            if (encryptedAccessTokenId != null) {
                redisDelete(encryptedAccessTokenIdKey, stringRedisTemplate);
                sendEmailConfirmationOnSuspiciousActivity(
                        aesStaticEncryptorDecryptor.decrypt(claims.get(EMAIL.name(), String.class)),
                        "Revoked or expired access token used when new access token already issued. Access token breach detected"
                );
            }
            throw new UnauthorizedException("Invalid token");
        }
        Client client = USER_AGENT_PARSER.parse(request.getHeader(USER_AGENT_HEADER));
        if (!client.device.family.equals(claims.get(DEVICE.name(), String.class)) ||
                !client.os.family.equals(claims.get(OS.name(), String.class)) ||
                !client.userAgent.family.equals(claims.get(AGENT.name(), String.class))) {
            redisDelete(encryptedAccessTokenId, stringRedisTemplate);
            sendEmailConfirmationOnSuspiciousActivity(
                    aesStaticEncryptorDecryptor.decrypt(claims.get(EMAIL.name(), String.class)),
                    "Access token used from different device. Access token breach detected"
            );
            throw new UnauthorizedException("Invalid token");
        }
        AuthenticationDto authentication = new AuthenticationDto();
        authentication.setUserId(userId);
        authentication.setUsername(claims.get(USERNAME.name(), String.class));
        authentication.setEmail(claims.get(EMAIL.name(), String.class));
        authentication.setRealEmail(claims.get(REAL_EMAIL.name(), String.class));
        authentication.setMfaEnabled(claims.get(MFA_ENABLED.name(), Boolean.class));
        authentication.setMfaMethods(claims.get(MFA_METHODS.name(), String.class));
        authentication.setAuthorities(claims.get(AUTHORITIES.name(), String.class));
        authentication.setEmailsFromExternalIdentities(claims.get(EMAILS_FROM_EXTERNAL_IDENTITIES.name(), String.class));
        return authentication;
    }

    private void sendEmailConfirmationOnSuspiciousActivity(String email,
                                                           String reason) throws Exception {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SUSPICIOUS_ACTIVITY.name())) {
            mailService.sendEmailAsync(email, "Suspicious Activity Detected", reason, SUSPICIOUS_ACTIVITY_CONFIRMATION);
        }
    }

    public void revokeAccessToken(UserModel user,
                                  HttpServletRequest request) throws Exception {
        redisDelete(getEncryptedAccessTokenIdKey(user, request), stringRedisTemplate);
    }

    public void logout(UserModel user,
                       HttpServletRequest request) throws Exception {
        Set<String> keys = new HashSet<>();
        keys.add(getEncryptedAccessTokenIdKey(user, request));
        String encryptedDeviceId = aesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER));
        redisRemoveZSetMember(
                getEncryptedDeviceIdsKey(user),
                encryptedDeviceId,
                stringRedisTemplate
        );
        redisRemoveHashMember(
                getEncryptedDeviceStatsKey(user),
                encryptedDeviceId,
                stringRedisTemplate
        );
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(user, request);
        keys.add(encryptedRefreshTokenKey);
        String encryptedRefreshToken = redisGet(encryptedRefreshTokenKey, stringRedisTemplate);
        if (encryptedRefreshToken != null) {
            String refreshToken = aesRandomEncryptorDecryptor.decrypt(encryptedRefreshToken);
            keys.add(getEncryptedRefreshTokenMappingKey(refreshToken));
            keys.add(getEncryptedRefreshTokenUserIdMappingKey(refreshToken));
        }
        redisDeleteAll(keys, stringRedisTemplate);
    }

    public void logoutFromDevices(UserModel user,
                                  Set<String> deviceIds) throws Exception {
        Set<String> keys = new HashSet<>();
        Set<String> validDeviceIds = new HashSet<>();
        String tempStr;
        for (String encryptedDeviceId : deviceIds) {
            if (encryptedDeviceId == null || encryptedDeviceId.isBlank()) {
                continue;
            }
            try {
                tempStr = aesStaticEncryptorDecryptor.decrypt(encryptedDeviceId);
            } catch (Exception ex) {
                continue;
            }
            validDeviceIds.add(encryptedDeviceId);
            keys.add(getEncryptedAccessTokenIdKey(user.getId(), tempStr));
            tempStr = getEncryptedRefreshTokenKey(user.getId(), tempStr);
            keys.add(tempStr);
            tempStr = redisGet(tempStr, stringRedisTemplate);
            if (tempStr != null) {
                tempStr = aesRandomEncryptorDecryptor.decrypt(tempStr);
                keys.add(getEncryptedRefreshTokenMappingKey(tempStr));
                keys.add(getEncryptedRefreshTokenUserIdMappingKey(tempStr));
            }
        }
        if (!keys.isEmpty()) {
            redisDeleteAll(keys, stringRedisTemplate);
            Object[] membersToRemove = validDeviceIds.toArray();
            redisRemoveZSetMembers(
                    getEncryptedDeviceIdsKey(user),
                    membersToRemove,
                    stringRedisTemplate
            );
            redisRemoveHashMembers(
                    getEncryptedDeviceStatsKey(user),
                    membersToRemove,
                    stringRedisTemplate
            );
        }
    }

    public void revokeTokens(Set<UserModel> users) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        for (UserModel user : users) {
            addMembers(
                    user.getId(),
                    encryptedKeys,
                    encryptedRefreshTokenKeys
            );
        }
        proceedAndRevokeTokens(encryptedKeys, encryptedRefreshTokenKeys);
    }

    private void addMembers(UUID userId,
                            Set<String> encryptedKeys,
                            Set<String> encryptedRefreshTokenKeys) throws Exception {
        String tempStr = getEncryptedDeviceIdsKey(userId);
        encryptedKeys.add(tempStr);
        encryptedKeys.add(getEncryptedDeviceStatsKey(userId));
        Set<String> members = redisGetAllZSetMembers(tempStr, stringRedisTemplate);
        if (members != null && !members.isEmpty()) {
            for (String encryptedDeviceId : members) {
                tempStr = aesStaticEncryptorDecryptor.decrypt(encryptedDeviceId);
                encryptedKeys.add(getEncryptedAccessTokenIdKey(userId, tempStr));
                tempStr = getEncryptedRefreshTokenKey(userId, tempStr);
                encryptedKeys.add(tempStr);
                encryptedRefreshTokenKeys.add(tempStr);
            }
        }
    }

    private void proceedAndRevokeTokens(Set<String> encryptedKeys,
                                        Set<String> encryptedRefreshTokenKeys) throws Exception {
        String decryptedRefreshToken;
        for (String encryptedRefreshToken : redisGetAll(encryptedRefreshTokenKeys, stringRedisTemplate)) {
            if (encryptedRefreshToken != null) {
                decryptedRefreshToken = aesRandomEncryptorDecryptor.decrypt(encryptedRefreshToken);
                encryptedKeys.add(getEncryptedRefreshTokenMappingKey(decryptedRefreshToken));
                encryptedKeys.add(getEncryptedRefreshTokenUserIdMappingKey(decryptedRefreshToken));
            }
        }
        if (!encryptedKeys.isEmpty()) {
            redisDeleteAll(encryptedKeys, stringRedisTemplate);
        }
    }

    public void revokeTokensByUsersIds(Set<UUID> usersIds) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        for (UUID userId : usersIds) {
            addMembers(
                    userId,
                    encryptedKeys,
                    encryptedRefreshTokenKeys
            );
        }
        proceedAndRevokeTokens(encryptedKeys, encryptedRefreshTokenKeys);
    }

    public void revokeRefreshToken(String refreshToken,
                                   String encryptedRefreshTokenMappingKey,
                                   String encryptedRefreshTokenUserIdMappingKey,
                                   String deviceId,
                                   String userId) throws Exception {
        if (encryptedRefreshTokenMappingKey == null) {
            encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKey(refreshToken);
        }
        Set<String> keys = new HashSet<>();
        keys.add(encryptedRefreshTokenMappingKey);
        if (encryptedRefreshTokenUserIdMappingKey == null) {
            encryptedRefreshTokenUserIdMappingKey = getEncryptedRefreshTokenUserIdMappingKey(refreshToken);
        }
        keys.add(encryptedRefreshTokenUserIdMappingKey);
        if (userId != null) {
            keys.add(getEncryptedRefreshTokenKey(
                    userId,
                    deviceId != null ? deviceId : getDeviceId(encryptedRefreshTokenMappingKey)
            ));
        } else {
            String encryptedUserId = redisGet(encryptedRefreshTokenUserIdMappingKey, stringRedisTemplate);
            if (encryptedUserId != null) {
                keys.add(getEncryptedRefreshTokenKey(
                        aesRandomEncryptorDecryptor.decrypt(encryptedUserId),
                        deviceId != null ? deviceId : getDeviceId(encryptedRefreshTokenMappingKey)
                ));
            } else {
                throw new SimpleBadRequestException("Invalid refresh token");
            }
        }
        redisDeleteAll(keys, stringRedisTemplate);
    }

    private String getDeviceId(String encryptedRefreshTokenMappingKey) throws Exception {
        String encryptedDeviceId = redisGet(encryptedRefreshTokenMappingKey, stringRedisTemplate);
        if (encryptedDeviceId != null) {
            return aesRandomEncryptorDecryptor.decrypt(encryptedDeviceId);
        }
        throw new SimpleBadRequestException("Invalid refresh token");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken,
                                                  HttpServletRequest request) throws Exception {
        String encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKey(refreshToken);
        String deviceId = getDeviceId(encryptedRefreshTokenMappingKey);
        if (!deviceId.equals(request.getHeader(X_DEVICE_ID_HEADER))) {
            revokeRefreshToken(
                    refreshToken,
                    encryptedRefreshTokenMappingKey,
                    null,
                    deviceId,
                    null
            );
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        String encryptedRefreshTokenUserIdMappingKey = getEncryptedRefreshTokenUserIdMappingKey(refreshToken);
        String userId = aesRandomEncryptorDecryptor.decrypt(redisGet(encryptedRefreshTokenUserIdMappingKey, stringRedisTemplate));
        String encryptedDeviceStatsKey = getEncryptedDeviceStatsKey(userId);
        String encryptedDeviceId = aesStaticEncryptorDecryptor.encrypt(deviceId);
        Object deviceStats = redisGetHashMember(
                encryptedDeviceStatsKey,
                encryptedDeviceId,
                stringRedisTemplate
        );
        if (deviceStats == null) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        String[] deviceInfo = aesRandomEncryptorDecryptor.decrypt((String) deviceStats).split(";");
        Client client = USER_AGENT_PARSER.parse(request.getHeader(USER_AGENT_HEADER));
        if (!client.device.family.equals(deviceInfo[0]) ||
                !deviceInfo[1].startsWith(client.os.family) ||
                !deviceInfo[2].startsWith(client.userAgent.family)) {
            revokeRefreshToken(
                    refreshToken,
                    encryptedRefreshTokenMappingKey,
                    encryptedRefreshTokenUserIdMappingKey,
                    deviceId,
                    userId
            );
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        UserModel user = dbServiceClient.getUserById(UUID.fromString(userId));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        Map<String, Object> tokens = generateAccessToken(
                user,
                request,
                encryptedDeviceId,
                encryptedDeviceStatsKey,
                client
        );
        tokens.put("refresh_token", generateRefreshToken(user, request));
        return tokens;
    }
}
