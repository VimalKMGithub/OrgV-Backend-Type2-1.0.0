package org.v.auth.service.services;

import io.getunleash.Unleash;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.v.auth.service.utils.AccessTokenUtility;
import org.v.commons.clients.DbServiceClient;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.enums.MfaType;
import org.v.commons.exceptions.ServiceUnavailableException;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.models.UserModel;
import org.v.commons.utils.UserUtility;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.v.auth.service.utils.AccessTokenUtility.ACCESS_TOKEN_EXPIRES_IN_SECONDS;
import static org.v.auth.service.utils.AccessTokenUtility.REFRESH_TOKEN_EXPIRES_IN_SECONDS;
import static org.v.auth.service.utils.QrUtility.encodeStringInQr;
import static org.v.commons.constants.HeadersCookies.*;
import static org.v.commons.enums.FeatureFlags.*;
import static org.v.commons.enums.MailType.OTP;
import static org.v.commons.enums.MailType.SELF_MFA_ENABLE_DISABLE_CONFIRMATION;
import static org.v.commons.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.v.commons.enums.MfaType.EMAIL_MFA;
import static org.v.commons.utils.CookieUtility.*;
import static org.v.commons.utils.MfaUtility.MFA_METHODS;
import static org.v.commons.utils.MfaUtility.getMfaType;
import static org.v.commons.utils.OtpUtility.generateOtp;
import static org.v.commons.utils.RedisServiceUtility.*;
import static org.v.commons.utils.ToggleUtility.getToggleAsBoolean;
import static org.v.commons.utils.TotpUtility.generateBase32Secret;
import static org.v.commons.utils.TotpUtility.verifyTotp;
import static org.v.commons.utils.UnleashServiceUtility.checkMfaGloballyEnabled;
import static org.v.commons.utils.UnleashServiceUtility.shouldDoMfa;
import static org.v.commons.utils.UserUtility.checkUserStatus;
import static org.v.commons.utils.UserUtility.getUserByUsernameOrEmailOrId;
import static org.v.commons.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class AuthService {
    private static final String STATE_TOKEN_PREFIX = "auth-service-state-token:";
    private static final String STATE_TOKEN_MAPPING_PREFIX = "auth-service-state-token-mapping:";
    private static final String EMAIL_MFA_OTP_PREFIX = "auth-service-email-mfa-otp:";
    private static final String AUTHENTICATOR_APP_SECRET_PREFIX = "auth-service-authenticator-app-secret:";
    private final DbServiceClient dbServiceClient;
    private final StringRedisTemplate stringRedisTemplate;
    private final Unleash unleash;
    private final AuthServiceMailService mailService;
    private final PasswordEncoder passwordEncoder;
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;
    private final AccessTokenUtility accessTokenUtility;

    public Map<String, Object> login(String usernameOrEmailOrId,
                                     String password,
                                     HttpServletRequest request,
                                     HttpServletResponse response) throws Exception {
        try {
            validateNotNullNotBlank(usernameOrEmailOrId, "User identifier");
            validatePassword(password);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid credentials");
        }
        UserModel user;
        try {
            user = getUserByUsernameOrEmailOrId(usernameOrEmailOrId, dbServiceClient, aesStaticEncryptorDecryptor);
        } catch (Exception ex) {
            throw new SimpleBadRequestException(ex.getMessage());
        }
        if (!passwordEncoder.matches(password, user.getPassword())) {
            handleFailedLogin(user);
            throw new SimpleBadRequestException("Invalid credentials");
        }
        checkUserStatus(user);
        return handleSuccessfulLogin(user, request, response);
    }

    private void handleFailedLogin(UserModel user) {
        user.recordFailedLoginAttempt();
        dbServiceClient.updateUser(user);
    }

    private Map<String, Object> handleSuccessfulLogin(UserModel user,
                                                      HttpServletRequest request,
                                                      HttpServletResponse response) throws Exception {
        if (unleash.isEnabled(MFA.name())) {
            if (shouldDoMfa(user, unleash)) {
                return Map.of(
                        "message", "Mfa required",
                        "state_token", generateStateToken(user),
                        "mfa_methods", user.getMfaMethods()
                );
            }
            if (unleash.isEnabled(FORCE_MFA.name())) {
                return Map.of(
                        "message", "Mfa required",
                        "state_token", generateStateToken(user),
                        "mfa_methods", Set.of(EMAIL_MFA)
                );
            }
        }
        Map<String, Object> tokens = accessTokenUtility.generateTokens(user, request);
        addHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                (String) tokens.get("access_token"),
                "Strict",
                "/",
                ACCESS_TOKEN_EXPIRES_IN_SECONDS
        );
        addHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                (String) tokens.get("refresh_token"),
                "Strict",
                "/",
                REFRESH_TOKEN_EXPIRES_IN_SECONDS
        );
        return Map.of("message", "Login successful");
    }

    private String generateStateToken(UserModel user) throws Exception {
        String encryptedStateTokenKey = getEncryptedStateTokenKey(user);
        String existingEncryptedStateToken = redisGet(encryptedStateTokenKey, stringRedisTemplate);
        if (existingEncryptedStateToken != null) {
            return aesRandomEncryptorDecryptor.decrypt(existingEncryptedStateToken);
        }
        String stateToken = UUID.randomUUID().toString();
        String encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        try {
            redisSave(
                    encryptedStateTokenKey,
                    aesRandomEncryptorDecryptor.encrypt(stateToken),
                    stringRedisTemplate
            );
            redisSave(
                    encryptedStateTokenMappingKey,
                    aesRandomEncryptorDecryptor.encrypt(user.getId().toString()),
                    stringRedisTemplate
            );
            return stateToken;
        } catch (Exception ex) {
            redisDeleteAll(
                    Set.of(encryptedStateTokenKey, encryptedStateTokenMappingKey),
                    stringRedisTemplate
            );
            throw new RuntimeException("Failed to generate state token", ex);
        }
    }

    private String getEncryptedStateTokenKey(UserModel user) throws Exception {
        return getEncryptedStateTokenKey(user.getId());
    }

    private String getEncryptedStateTokenKey(UUID userId) throws Exception {
        return getEncryptedStateTokenKey(userId.toString());
    }

    private String getEncryptedStateTokenKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_PREFIX + userId);
    }

    private String getEncryptedStateTokenMappingKey(String stateToken) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
    }

    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        accessTokenUtility.logout(user, request);
        removeHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        removeHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        return Map.of("message", "Logout successful");
    }

    public Map<String, String> logoutFromDevices(Set<String> deviceIds,
                                                 HttpServletRequest request,
                                                 HttpServletResponse response) throws Exception {
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        accessTokenUtility.logoutFromDevices(user, deviceIds);
        if (deviceIds.contains(request.getHeader(X_DEVICE_ID_HEADER))) {
            removeHttpOnlyCookie(
                    response,
                    ACCESS_TOKEN_COOKIE,
                    "Strict",
                    "/"
            );
            removeHttpOnlyCookie(
                    response,
                    REFRESH_TOKEN_COOKIE,
                    "Strict",
                    "/"
            );
        }
        return Map.of("message", "Logout from devices successful");
    }

    public Map<String, String> logoutAllDevices(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        accessTokenUtility.revokeTokens(Set.of(user));
        removeHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        removeHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        return Map.of("message", "Logout from all devices successful");
    }

    public Map<String, Object> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String refreshToken = getCookieValue(request, REFRESH_TOKEN_COOKIE);
        try {
            validateUuid(refreshToken);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        Map<String, Object> tokens = accessTokenUtility.refreshAccessToken(refreshToken, request);
        addHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                (String) tokens.get("access_token"),
                "Strict",
                "/",
                ACCESS_TOKEN_EXPIRES_IN_SECONDS
        );
        addHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                (String) tokens.get("refresh_token"),
                "Strict",
                "/",
                REFRESH_TOKEN_EXPIRES_IN_SECONDS
        );
        return Map.of("message", "Access token refreshed successfully");
    }

    public Map<String, String> revokeAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        accessTokenUtility.revokeAccessToken(user, request);
        removeHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        return Map.of("message", "Access token revoked successfully");
    }

    public Map<String, String> revokeRefreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String refreshToken = getCookieValue(request, REFRESH_TOKEN_COOKIE);
        try {
            validateUuid(refreshToken);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        accessTokenUtility.revokeRefreshToken(
                refreshToken,
                null,
                null,
                null,
                null
        );
        removeHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        return Map.of("message", "Refresh token revoked successfully");
    }

    public ResponseEntity<Object> requestToToggleMfa(String type,
                                                     String toggle,
                                                     HttpServletRequest request) throws Exception {
        boolean toggleEnabled = getToggleAsBoolean(toggle);
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        user.setUsername(request.getHeader(X_USERNAME_HEADER));
        user.setEmail(request.getHeader(X_EMAIL_HEADER));
        setMfaMethodsFromHeader(user, request);
        return proceedRequestToToggleMfa(
                user,
                checkConditionsForMfaType(type, user, toggleEnabled),
                toggleEnabled
        );
    }

    private void setMfaMethodsFromHeader(UserModel user,
                                         HttpServletRequest request) {
        UserUtility.setMfaMethodsFromHeader(user, request.getHeader(X_MFA_METHODS_HEADER));
    }

    private MfaType checkConditionsForMfaType(String type,
                                              UserModel user,
                                              boolean toggleEnabled) {
        MfaType mfaType = getMfaType(type);
        checkMfaGloballyEnabled(unleash);
        if (!unleash.isEnabled(mfaType.toFeatureFlag().name())) {
            throw new ServiceUnavailableException(type + " Mfa is disabled globally");
        }
        boolean doesUserHasGivenMfaType = user.hasMfaMethod(mfaType);
        if (toggleEnabled && doesUserHasGivenMfaType) {
            throw new SimpleBadRequestException(type + " Mfa is already enabled");
        }
        if (!toggleEnabled && !doesUserHasGivenMfaType) {
            throw new SimpleBadRequestException(type + " Mfa is already disabled");
        }
        return mfaType;
    }

    private ResponseEntity<Object> proceedRequestToToggleMfa(UserModel user,
                                                             MfaType type,
                                                             boolean toggleEnabled) throws Exception {
        if (toggleEnabled) {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(
                            aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                            "Otp to enable email Mfa",
                            generateOtpForEmailMfa(user),
                            OTP
                    );
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok()
                            .contentType(MediaType.IMAGE_PNG)
                            .body(generateQrCodeForAuthenticatorApp(user));
                }
            }
        } else {
            switch (type) {
                case EMAIL_MFA -> {
                    mailService.sendEmailAsync(
                            aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                            "Otp to disable email Mfa",
                            generateOtpForEmailMfa(user),
                            OTP
                    );
                    return ResponseEntity.ok(Map.of("message", "Otp sent to your registered email address. Please check your email to continue"));
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return ResponseEntity.ok(Map.of("message", "Please proceed to verify Totp"));
                }
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private String generateOtpForEmailMfa(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedEmailMfaOtpKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedEmailMfaOtpKey(UserModel user) throws Exception {
        return getEncryptedEmailMfaOtpKey(user.getId());
    }

    private String getEncryptedEmailMfaOtpKey(UUID userId) throws Exception {
        return getEncryptedEmailMfaOtpKey(userId.toString());
    }

    private String getEncryptedEmailMfaOtpKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_MFA_OTP_PREFIX + userId);
    }

    private byte[] generateQrCodeForAuthenticatorApp(UserModel user) throws Exception {
        return encodeStringInQr(generateTotpUrl(
                        "OrgV",
                        aesStaticEncryptorDecryptor.decrypt(user.getUsername()),
                        generateAuthenticatorAppSecret(user)
                )
        );
    }

    private String generateTotpUrl(String issuer,
                                   String accountName,
                                   String base32Secret) {
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                urlEncode(issuer),
                urlEncode(accountName),
                base32Secret,
                urlEncode(issuer)
        );
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String generateAuthenticatorAppSecret(UserModel user) throws Exception {
        String secret = generateBase32Secret();
        redisSave(
                getEncryptedSecretKey(user),
                aesRandomEncryptorDecryptor.encrypt(secret),
                stringRedisTemplate
        );
        return secret;
    }

    private String getEncryptedSecretKey(UserModel user) throws Exception {
        return getEncryptedSecretKey(user.getId());
    }

    private String getEncryptedSecretKey(UUID userId) throws Exception {
        return getEncryptedSecretKey(userId.toString());
    }

    private String getEncryptedSecretKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + userId);
    }

    public Map<String, String> verifyToggleMfa(String type,
                                               String toggle,
                                               String otpTotp,
                                               HttpServletRequest request,
                                               HttpServletResponse response) throws Exception {
        boolean toggleEnabled = getToggleAsBoolean(toggle);
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        user.setUsername(request.getHeader(X_USERNAME_HEADER));
        user.setEmail(request.getHeader(X_EMAIL_HEADER));
        setMfaMethodsFromHeader(user, request);
        return proceedToVerifyToggleMfa(
                user,
                checkConditionsForMfaType(type, user, toggleEnabled),
                toggleEnabled,
                otpTotp,
                response
        );
    }

    private Map<String, String> proceedToVerifyToggleMfa(UserModel user,
                                                         MfaType type,
                                                         boolean toggleEnabled,
                                                         String otpTotp,
                                                         HttpServletResponse response) throws Exception {
        if (toggleEnabled) {
            switch (type) {
                case EMAIL_MFA -> {
                    return verifyOtpToToggleEmailMfa(user, otpTotp, true, response);
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return verifyTotpToEnableAuthenticatorAppMfa(user, otpTotp, response);
                }
            }
        } else {
            switch (type) {
                case EMAIL_MFA -> {
                    return verifyOtpToToggleEmailMfa(user, otpTotp, false, response);
                }
                case AUTHENTICATOR_APP_MFA -> {
                    return verifyTotpToDisableAuthenticatorAppMfa(user, otpTotp, response);
                }
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, String> verifyOtpToToggleEmailMfa(UserModel user,
                                                          String otp,
                                                          boolean toggle,
                                                          HttpServletResponse response) throws Exception {
        validateOtp(otp, 6);
        String encryptedEmailMfaOtpKey = getEncryptedEmailMfaOtpKey(user);
        String encryptedOtp = redisGet(encryptedEmailMfaOtpKey, stringRedisTemplate);
        if (encryptedOtp != null) {
            if (aesRandomEncryptorDecryptor.decrypt(encryptedOtp).equals(otp)) {
                try {
                    redisDelete(encryptedEmailMfaOtpKey, stringRedisTemplate);
                } catch (Exception ignored) {
                }
                user = dbServiceClient.getUserById(user.getId());
                if (user == null) {
                    throw new SimpleBadRequestException("Invalid user");
                }
                if (toggle) {
                    user.addMfaMethod(EMAIL_MFA);
                } else {
                    user.removeMfaMethod(EMAIL_MFA);
                }
                user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
                accessTokenUtility.revokeTokens(Set.of(user));
                removeHttpOnlyCookie(
                        response,
                        ACCESS_TOKEN_COOKIE,
                        "Strict",
                        "/"
                );
                removeHttpOnlyCookie(
                        response,
                        REFRESH_TOKEN_COOKIE,
                        "Strict",
                        "/"
                );
                dbServiceClient.updateUser(user);
                emailConfirmationOnMfaToggle(user, EMAIL_MFA, toggle);
                if (toggle) {
                    return Map.of("message", "Email Mfa enabled successfully. Please log in again to continue");
                } else {
                    return Map.of("message", "Email Mfa disabled successfully. Please log in again to continue");
                }
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void emailConfirmationOnMfaToggle(UserModel user,
                                              MfaType type,
                                              boolean toggle) throws Exception {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_MFA_ENABLE_DISABLE.name())) {
            String action = toggle ? "enabled" : "disabled";
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "Mfa " + action + " confirmation",
                    "Your " + type + " Mfa has been " + action,
                    SELF_MFA_ENABLE_DISABLE_CONFIRMATION
            );
        }
    }

    private Map<String, String> verifyTotpToEnableAuthenticatorAppMfa(UserModel user,
                                                                      String totp,
                                                                      HttpServletResponse response) throws Exception {
        validateOtp(totp, 6);
        String encryptedSecretKey = getEncryptedSecretKey(user);
        String encryptedSecret = redisGet(encryptedSecretKey, stringRedisTemplate);
        if (encryptedSecret != null) {
            String secret = aesRandomEncryptorDecryptor.decrypt(encryptedSecret);
            if (verifyTotp(secret, totp)) {
                try {
                    redisDelete(encryptedSecretKey, stringRedisTemplate);
                } catch (Exception ignored) {
                }
                user = dbServiceClient.getUserById(user.getId());
                if (user == null) {
                    throw new SimpleBadRequestException("Invalid user");
                }
                user.addMfaMethod(AUTHENTICATOR_APP_MFA);
                user.setAuthAppSecret(aesRandomEncryptorDecryptor.encrypt(secret));
                user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
                accessTokenUtility.revokeTokens(Set.of(user));
                removeHttpOnlyCookie(
                        response,
                        ACCESS_TOKEN_COOKIE,
                        "Strict",
                        "/"
                );
                removeHttpOnlyCookie(
                        response,
                        REFRESH_TOKEN_COOKIE,
                        "Strict",
                        "/"
                );
                dbServiceClient.updateUser(user);
                emailConfirmationOnMfaToggle(user, AUTHENTICATOR_APP_MFA, true);
                return Map.of("message", "Authenticator app Mfa enabled successfully. Please log in again to continue");
            }
            throw new SimpleBadRequestException("Invalid Totp");
        }
        throw new SimpleBadRequestException("Invalid Totp");
    }

    private Map<String, String> verifyTotpToDisableAuthenticatorAppMfa(UserModel user,
                                                                       String totp,
                                                                       HttpServletResponse response) throws Exception {
        validateOtp(totp, 6);
        user = dbServiceClient.getUserById(user.getId());
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        if (!verifyTotp(aesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()), totp)) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        user.removeMfaMethod(AUTHENTICATOR_APP_MFA);
        user.setAuthAppSecret(null);
        user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
        accessTokenUtility.revokeTokens(Set.of(user));
        removeHttpOnlyCookie(
                response,
                ACCESS_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        removeHttpOnlyCookie(
                response,
                REFRESH_TOKEN_COOKIE,
                "Strict",
                "/"
        );
        dbServiceClient.updateUser(user);
        emailConfirmationOnMfaToggle(user, AUTHENTICATOR_APP_MFA, false);
        return Map.of("message", "Authenticator app Mfa disabled successfully. Please log in again to continue");
    }

    public Map<String, String> requestToLoginByMfa(String type,
                                                   String stateToken) throws Exception {
        MfaType mfaType = getMfaType(type);
        checkMfaGloballyEnabled(unleash);
        try {
            validateUuid(stateToken);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid state token");
        }
        UserModel user = getUserByStateToken(stateToken);
        switch (mfaType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return sendEmailOtpToLoginMfa(user);
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return sendEmailOtpToLoginMfa(user);
                } else {
                    throw new SimpleBadRequestException("Email Mfa is not enabled");
                }
            }
            case AUTHENTICATOR_APP_MFA -> {
                if (!unleash.isEnabled(MFA_AUTHENTICATOR_APP.name())) {
                    throw new ServiceUnavailableException("Authenticator app Mfa is disabled globally");
                }
                if (!user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                    throw new SimpleBadRequestException("Authenticator app Mfa is not enabled");
                }
                return Map.of("message", "Please proceed to verify Totp");
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private UserModel getUserByStateToken(String stateToken) throws Exception {
        UserModel user = dbServiceClient.getUserById(UUID.fromString(getUserIdFromEncryptedStateTokenMappingKey(getEncryptedStateTokenMappingKey(stateToken))));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid state token");
        }
        checkUserStatus(user);
        return user;
    }

    private String getUserIdFromEncryptedStateTokenMappingKey(String encryptedStateTokenMappingKey) throws Exception {
        String encryptedUserId = redisGet(encryptedStateTokenMappingKey, stringRedisTemplate);
        if (encryptedUserId != null) {
            return aesRandomEncryptorDecryptor.decrypt(encryptedUserId);
        }
        throw new SimpleBadRequestException("Invalid state token");
    }

    private Map<String, String> sendEmailOtpToLoginMfa(UserModel user) throws Exception {
        mailService.sendEmailAsync(
                aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                "Otp to verify email Mfa to login",
                generateOtpForEmailMfa(user),
                OTP
        );
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    public Map<String, Object> verifyMfaToLogin(String type,
                                                String stateToken,
                                                String otpTotp,
                                                HttpServletRequest request,
                                                HttpServletResponse response) throws Exception {
        MfaType mfaType = getMfaType(type);
        checkMfaGloballyEnabled(unleash);
        try {
            validateUuid(stateToken);
            validateOtp(otpTotp, 6);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid state token or otp/totp");
        }
        String encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        UserModel user = dbServiceClient.getUserById(UUID.fromString(getUserIdFromEncryptedStateTokenMappingKey(encryptedStateTokenMappingKey)));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid state token");
        }
        checkUserStatus(user);
        switch (mfaType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return verifyEmailOtpToLogin(user, otpTotp, encryptedStateTokenMappingKey, request, response);
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return verifyEmailOtpToLogin(user, otpTotp, encryptedStateTokenMappingKey, request, response);
                } else {
                    throw new SimpleBadRequestException("Email Mfa is not enabled");
                }
            }
            case AUTHENTICATOR_APP_MFA -> {
                if (!unleash.isEnabled(MFA_AUTHENTICATOR_APP.name())) {
                    throw new ServiceUnavailableException("Authenticator app Mfa is disabled globally");
                }
                if (!user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                    throw new SimpleBadRequestException("Authenticator app Mfa is not enabled");
                }
                return verifyAuthenticatorAppTotpToLogin(user, otpTotp, encryptedStateTokenMappingKey, request, response);
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToLogin(UserModel user,
                                                      String otp,
                                                      String encryptedStateTokenMappingKey,
                                                      HttpServletRequest request,
                                                      HttpServletResponse response) throws Exception {
        checkUserStatus(user);
        String encryptedEmailMfaOtpKey = getEncryptedEmailMfaOtpKey(user);
        String encryptedOtp = redisGet(encryptedEmailMfaOtpKey, stringRedisTemplate);
        if (encryptedOtp != null) {
            if (aesRandomEncryptorDecryptor.decrypt(encryptedOtp).equals(otp)) {
                try {
                    redisDeleteAll(
                            Set.of(
                                    getEncryptedStateTokenKey(user),
                                    encryptedStateTokenMappingKey,
                                    encryptedEmailMfaOtpKey
                            ),
                            stringRedisTemplate
                    );
                } catch (Exception ignored) {
                }
                Map<String, Object> tokens = accessTokenUtility.generateTokens(user, request);
                addHttpOnlyCookie(
                        response,
                        ACCESS_TOKEN_COOKIE,
                        (String) tokens.get("access_token"),
                        "Strict",
                        "/",
                        ACCESS_TOKEN_EXPIRES_IN_SECONDS
                );
                addHttpOnlyCookie(
                        response,
                        REFRESH_TOKEN_COOKIE,
                        (String) tokens.get("refresh_token"),
                        "Strict",
                        "/",
                        REFRESH_TOKEN_EXPIRES_IN_SECONDS
                );
                return Map.of("message", "Login successful");
            }
            handleFailedMfaLoginAttempt(user);
            throw new SimpleBadRequestException("Invalid Otp");
        }
        handleFailedMfaLoginAttempt(user);
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void handleFailedMfaLoginAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        dbServiceClient.updateUser(user);
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToLogin(UserModel user,
                                                                  String totp,
                                                                  String encryptedStateTokenMappingKey,
                                                                  HttpServletRequest request,
                                                                  HttpServletResponse response) throws Exception {
        checkUserStatus(user);
        if (verifyTotp(aesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()), totp)) {
            try {
                redisDeleteAll(
                        Set.of(getEncryptedStateTokenKey(user), encryptedStateTokenMappingKey),
                        stringRedisTemplate
                );
            } catch (Exception ignored) {
            }
            Map<String, Object> tokens = accessTokenUtility.generateTokens(user, request);
            addHttpOnlyCookie(
                    response,
                    ACCESS_TOKEN_COOKIE,
                    (String) tokens.get("access_token"),
                    "Strict",
                    "/",
                    ACCESS_TOKEN_EXPIRES_IN_SECONDS
            );
            addHttpOnlyCookie(
                    response,
                    REFRESH_TOKEN_COOKIE,
                    (String) tokens.get("refresh_token"),
                    "Strict",
                    "/",
                    REFRESH_TOKEN_EXPIRES_IN_SECONDS
            );
            return Map.of("message", "Login successful");
        }
        handleFailedMfaLoginAttempt(user);
        throw new SimpleBadRequestException("Invalid Totp");
    }

    public Map<Object, Object> getActiveDevices(HttpServletRequest request) throws Exception {
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        Map<Object, Object> response = redisGetAllHashMembers(accessTokenUtility.getEncryptedDeviceStatsKey(user), stringRedisTemplate);
        for (Map.Entry<Object, Object> entry : response.entrySet()) {
            entry.setValue(aesRandomEncryptorDecryptor.decrypt((String) entry.getValue()));
        }
        response.put("current_device_id", aesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER)));
        return response;
    }
}
