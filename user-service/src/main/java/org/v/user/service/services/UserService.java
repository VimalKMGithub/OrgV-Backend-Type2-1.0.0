package org.v.user.service.services;

import io.getunleash.Unleash;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.v.commons.clients.AuthServiceClient;
import org.v.commons.clients.DbServiceClient;
import org.v.commons.dtos.RegistrationDto;
import org.v.commons.dtos.ResetPasswordDto;
import org.v.commons.dtos.UserSummaryDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.enums.MfaType;
import org.v.commons.exceptions.ServiceUnavailableException;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.models.UserModel;
import org.v.commons.utils.MapperUtility;
import org.v.commons.utils.UserUtility;
import org.v.user.service.dtos.ChangePasswordDto;
import org.v.user.service.dtos.SelfUpdationDto;
import org.v.user.service.dtos.SelfUpdationResultDto;

import java.util.*;

import static org.v.commons.constants.HeadersCookies.*;
import static org.v.commons.enums.FeatureFlags.*;
import static org.v.commons.enums.MailType.*;
import static org.v.commons.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.v.commons.enums.MfaType.EMAIL_MFA;
import static org.v.commons.utils.MailUtility.normalizeEmail;
import static org.v.commons.utils.MfaUtility.MFA_METHODS;
import static org.v.commons.utils.MfaUtility.getMfaType;
import static org.v.commons.utils.OtpUtility.generateOtp;
import static org.v.commons.utils.RedisServiceUtility.*;
import static org.v.commons.utils.TotpUtility.verifyTotp;
import static org.v.commons.utils.UnleashServiceUtility.checkMfaGloballyEnabled;
import static org.v.commons.utils.UnleashServiceUtility.shouldDoMfa;
import static org.v.commons.utils.UserUtility.*;
import static org.v.commons.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "user-service-email-verification-token:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "user-service-email-verification-token-mapping:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "user-service-forgot-password-otp:";
    private static final String EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX = "user-service-email-otp-for-password-change:";
    private static final String EMAIL_STORE_PREFIX = "user-service-email-store:";
    private static final String EMAIL_CHANGE_OTP_FOR_NEW_EMAIL_PREFIX = "user-service-email-change-otp-for-new-email:";
    private static final String EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX = "user-service-email-change-otp-for-old-email:";
    private static final String EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX = "user-service-email-otp-to-delete-account:";
    private final DbServiceClient dbServiceClient;
    private final AuthServiceClient authServiceClient;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate stringRedisTemplate;
    private final UserServiceMailService mailService;
    private final Unleash unleash;
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;
    private final MapperUtility mapperUtility;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) throws Exception {
        if (unleash.isEnabled(REGISTRATION_ENABLED.name())) {
            Set<String> invalidInputs = validateRegistrationInputs(dto);
            if (!invalidInputs.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
            }
            String encryptedUsername = aesStaticEncryptorDecryptor.encrypt(dto.getUsername());
            if (dbServiceClient.existsByUsername(encryptedUsername)) {
                throw new SimpleBadRequestException("Username: '" + dto.getUsername() + "' is already taken");
            }
            String encryptedEmail = aesStaticEncryptorDecryptor.encrypt(dto.getEmail());
            if (dbServiceClient.existsByEmail(encryptedEmail)) {
                throw new SimpleBadRequestException("Email: '" + dto.getEmail() + "' is already taken");
            }
            String encryptedNormalizedEmail = aesStaticEncryptorDecryptor.encrypt(normalizeEmail(dto.getEmail()));
            if (dbServiceClient.existsByRealEmail(encryptedNormalizedEmail)) {
                throw new SimpleBadRequestException("Email: '" + dto.getEmail() + "' is already taken");
            }
            if (dbServiceClient.externalIdentityExistsByEmail(encryptedNormalizedEmail)) {
                throw new SimpleBadRequestException("Email: '" + dto.getEmail() + "' is already taken");
            }
            UserModel user = toUserModel(
                    dto,
                    encryptedUsername,
                    encryptedEmail,
                    encryptedNormalizedEmail
            );
            boolean shouldVerifyRegisteredEmail = unleash.isEnabled(REGISTRATION_EMAIL_VERIFICATION.name());
            user.setEmailVerified(!shouldVerifyRegisteredEmail);
            user = dbServiceClient.createUser(user);
            Map<String, Object> response = new HashMap<>();
            if (shouldVerifyRegisteredEmail) {
                mailService.sendEmailAsync(
                        dto.getEmail(),
                        "Email verification link after registration",
                        "http://localhost:3000/verify-email?emailVerificationToken=" + generateEmailVerificationToken(user),
                        LINK
                );
                response.put("message", "Registration successful. Please check your email for verification link");
            } else {
                response.put("message", "Registration successful");
            }
            response.put("user", mapperUtility.toUserSummaryDto(user));
            return ResponseEntity.ok(response);
        }
        throw new ServiceUnavailableException("Registration is currently disabled. Please try again later");
    }

    private UserModel toUserModel(RegistrationDto dto,
                                  String encryptedUsername,
                                  String encryptedEmail,
                                  String encryptedNormalizedEmail) throws Exception {
        return UserModel.builder()
                .username(encryptedUsername)
                .email(encryptedEmail)
                .realEmail(encryptedNormalizedEmail)
                .password(passwordEncoder.encode(dto.getPassword()))
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .createdBy(aesRandomEncryptorDecryptor.encrypt("SELF"))
                .build();
    }

    private String generateEmailVerificationToken(UserModel user) throws Exception {
        String encryptedEmailVerificationTokenKey = getEncryptedEmailVerificationTokenKey(user);
        String existingEncryptedEmailVerificationToken = redisGet(encryptedEmailVerificationTokenKey, stringRedisTemplate);
        if (existingEncryptedEmailVerificationToken != null) {
            return aesRandomEncryptorDecryptor.decrypt(existingEncryptedEmailVerificationToken);
        }
        String emailVerificationToken = UUID.randomUUID().toString();
        String encryptedEmailVerificationTokenMappingKey = getEncryptedEmailVerificationTokenMappingKey(emailVerificationToken);
        try {
            redisSave(
                    encryptedEmailVerificationTokenKey,
                    aesRandomEncryptorDecryptor.encrypt(emailVerificationToken),
                    stringRedisTemplate
            );
            redisSave(
                    encryptedEmailVerificationTokenMappingKey,
                    aesRandomEncryptorDecryptor.encrypt(user.getId().toString()),
                    stringRedisTemplate
            );
            return emailVerificationToken;
        } catch (Exception ex) {
            redisDeleteAll(
                    Set.of(encryptedEmailVerificationTokenKey, encryptedEmailVerificationTokenMappingKey),
                    stringRedisTemplate
            );
            throw new RuntimeException("Failed to generate email verification token", ex);
        }
    }

    private String getEncryptedEmailVerificationTokenKey(UserModel user) throws Exception {
        return getEncryptedEmailVerificationTokenKey(user.getId());
    }

    private String getEncryptedEmailVerificationTokenKey(UUID userId) throws Exception {
        return getEncryptedEmailVerificationTokenKey(userId.toString());
    }

    private String getEncryptedEmailVerificationTokenKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_VERIFICATION_TOKEN_PREFIX + userId);
    }

    private String getEncryptedEmailVerificationTokenMappingKey(String emailVerificationToken) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
    }

    public Map<String, Object> verifyEmail(String emailVerificationToken) throws Exception {
        try {
            validateUuid(emailVerificationToken);
        } catch (SimpleBadRequestException ex) {
            throw new SimpleBadRequestException("Invalid email verification token");
        }
        String encryptedEmailVerificationTokenMappingKey = getEncryptedEmailVerificationTokenMappingKey(emailVerificationToken);
        UserModel user = dbServiceClient.getUserById(UUID.fromString(getUserIdFromEncryptedEmailVerificationTokenMappingKey(encryptedEmailVerificationTokenMappingKey)));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid email verification token");
        }
        checkDeletedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
        if (user.isEmailVerified()) {
            throw new SimpleBadRequestException("Email is already verified");
        }
        user.setEmailVerified(true);
        user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
        try {
            redisDeleteAll(Set.of(getEncryptedEmailVerificationTokenKey(user), encryptedEmailVerificationTokenMappingKey), stringRedisTemplate);
        } catch (Exception ignored) {
        }
        return Map.of(
                "message", "Email verification successful",
                "user", mapperUtility.toUserSummaryDto(dbServiceClient.updateUser(user))
        );
    }

    private String getUserIdFromEncryptedEmailVerificationTokenMappingKey(String encryptedEmailVerificationTokenMappingKey) throws Exception {
        String encryptedUserId = redisGet(encryptedEmailVerificationTokenMappingKey, stringRedisTemplate);
        if (encryptedUserId != null) {
            return aesRandomEncryptorDecryptor.decrypt(encryptedUserId);
        }
        throw new SimpleBadRequestException("Invalid email verification token");
    }

    public Map<String, String> resendEmailVerificationLink(String usernameOrEmailOrId) throws Exception {
        if (unleash.isEnabled(RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            return proceedResendEmailVerificationLink(getUserByUsernameOrEmailOrId(usernameOrEmailOrId, dbServiceClient, aesStaticEncryptorDecryptor));
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    private Map<String, String> proceedResendEmailVerificationLink(UserModel user) throws Exception {
        checkDeletedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
        if (user.isEmailVerified()) {
            throw new SimpleBadRequestException("Email is already verified");
        }
        mailService.sendEmailAsync(
                aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                "Resending email verification link after registration",
                "http://localhost:3000/verify-email?emailVerificationToken=" + generateEmailVerificationToken(user),
                LINK
        );
        return Map.of("message", "Email verification link resent successfully. Please check your email");
    }

    public UserSummaryDto selfDetails(HttpServletRequest request) throws Exception {
        UserModel user = dbServiceClient.getUserById(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        return mapperUtility.toUserSummaryDto(user);
    }

    public ResponseEntity<Map<String, Object>> forgotPassword(String usernameOrEmailOrId) throws Exception {
        UserModel user = getUserByUsernameOrEmailOrId(usernameOrEmailOrId, dbServiceClient, aesStaticEncryptorDecryptor);
        checkDeletedStatus(user);
        checkEmailVerifiedStatus(user);
        checkLockedStatus(user);
        checkEnabledStatus(user);
        checkExpiredStatus(user);
        Set<MfaType> methods = user.getMfaMethods();
        methods.add(EMAIL_MFA);
        return ResponseEntity.ok(Map.of("message", "Please select a method for password reset", "methods", methods));
    }

    public Map<String, String> forgotPasswordMethodSelection(String usernameOrEmailOrId,
                                                             String method) throws Exception {
        MfaType mfaType = getMfaType(method);
        UserModel user = getUserByUsernameOrEmailOrId(usernameOrEmailOrId, dbServiceClient, aesStaticEncryptorDecryptor);
        checkDeletedStatus(user);
        checkEmailVerifiedStatus(user);
        checkLockedStatus(user);
        checkEnabledStatus(user);
        checkExpiredStatus(user);
        Set<MfaType> methods = user.getMfaMethods();
        methods.add(EMAIL_MFA);
        if (!methods.contains(mfaType)) {
            throw new SimpleBadRequestException("Mfa method: '" + method + "' is not enabled for user");
        }
        switch (mfaType) {
            case EMAIL_MFA -> {
                mailService.sendEmailAsync(
                        aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                        "Otp for resetting password",
                        generateOtpForForgotPassword(user),
                        OTP
                );
                return Map.of("message", "Otp sent to your email. Please check your email to reset your password");
            }
            case AUTHENTICATOR_APP_MFA -> {
                return Map.of("message", "Please proceed to verify Totp");
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
    }

    private String generateOtpForForgotPassword(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedForgotPasswordOtpKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedForgotPasswordOtpKey(UserModel user) throws Exception {
        return getEncryptedForgotPasswordOtpKey(user.getId());
    }

    private String getEncryptedForgotPasswordOtpKey(UUID userId) throws Exception {
        return getEncryptedForgotPasswordOtpKey(userId.toString());
    }

    private String getEncryptedForgotPasswordOtpKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(FORGOT_PASSWORD_OTP_PREFIX + userId);
    }

    public ResponseEntity<Map<String, Object>> resetPassword(ResetPasswordDto dto) throws Exception {
        MfaType mfaType = getMfaType(dto.getMethod());
        Set<String> invalidInputs = validateResetPasswordInputs(dto);
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        UserModel user = getUserByUsernameOrEmailOrId(dto.getUsernameOrEmailOrId(), dbServiceClient, aesStaticEncryptorDecryptor);
        checkDeletedStatus(user);
        checkEmailVerifiedStatus(user);
        checkLockedStatus(user);
        checkEnabledStatus(user);
        checkExpiredStatus(user);
        Set<MfaType> methods = new HashSet<>(user.getMfaMethods());
        methods.add(EMAIL_MFA);
        if (!methods.contains(mfaType)) {
            throw new SimpleBadRequestException("Mfa method: '" + dto.getMethod() + "' is not enabled for user");
        }
        switch (mfaType) {
            case EMAIL_MFA -> {
                return ResponseEntity.ok(verifyEmailOtpToResetPassword(user, dto));
            }
            case AUTHENTICATOR_APP_MFA -> {
                return ResponseEntity.ok(verifyAuthenticatorAppTotpToResetPassword(user, dto));
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + dto.getMethod() + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToResetPassword(UserModel user,
                                                              ResetPasswordDto dto) throws Exception {
        String encryptedForgotPasswordOtpKey = getEncryptedForgotPasswordOtpKey(user);
        String encryptedOtp = redisGet(encryptedForgotPasswordOtpKey, stringRedisTemplate);
        if (encryptedOtp != null) {
            if (aesRandomEncryptorDecryptor.decrypt(encryptedOtp).equals(dto.getOtpTotp())) {
                try {
                    redisDelete(encryptedForgotPasswordOtpKey, stringRedisTemplate);
                } catch (Exception ignored) {
                }
                authServiceClient.revokeTokens(Set.of(user));
                selfChangePassword(user, dto.getNewPassword());
                emailConfirmationOnPasswordReset(user);
                return Map.of("message", "Password reset successful");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private void selfChangePassword(UserModel user,
                                    String password) throws Exception {
        user.recordPasswordChange(passwordEncoder.encode(password));
        user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
        dbServiceClient.updateUser(user);
    }

    private void emailConfirmationOnPasswordReset(UserModel user) throws Exception {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_PASSWORD_RESET.name())) {
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "Password reset confirmation",
                    "",
                    PASSWORD_RESET_CONFIRMATION
            );
        }
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToResetPassword(UserModel user,
                                                                          ResetPasswordDto dto) throws Exception {
        if (!verifyTotp(aesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()), dto.getOtpTotp())) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        authServiceClient.revokeTokens(Set.of(user));
        selfChangePassword(user, dto.getNewPassword());
        emailConfirmationOnPasswordReset(user);
        return Map.of("message", "Password reset successful");
    }

    public ResponseEntity<Map<String, Object>> changePassword(ChangePasswordDto dto,
                                                              HttpServletRequest request) throws Exception {
        Set<String> invalidInputs = validateNewAndConfirmNewPassword(dto);
        try {
            validatePassword(dto.getOldPassword());
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid old password");
        }
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        user.setMfaEnabled(Boolean.parseBoolean(request.getHeader(X_MFA_ENABLED_HEADER)));
        setMfaMethodsFromHeader(user, request);
        if (unleash.isEnabled(MFA.name())) {
            if (shouldDoMfa(user, unleash)) {
                return ResponseEntity.ok(Map.of("message", "Please select a method to password change", "methods", user.getMfaMethods()));
            }
            if (unleash.isEnabled(FORCE_MFA.name())) {
                return ResponseEntity.ok(Map.of("message", "Please select a method to password change", "methods", Set.of(EMAIL_MFA)));
            }
        }
        user = dbServiceClient.getUserById(user.getId());
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        checkDeletedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            throw new SimpleBadRequestException("Old password is incorrect");
        }
        authServiceClient.revokeTokens(Set.of(user));
        selfChangePassword(user, dto.getNewPassword());
        emailConfirmationOnSelfPasswordChange(user);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    private void setMfaMethodsFromHeader(UserModel user,
                                         HttpServletRequest request) {
        UserUtility.setMfaMethodsFromHeader(user, request.getHeader(X_MFA_METHODS_HEADER));
    }

    private void emailConfirmationOnSelfPasswordChange(UserModel user) throws Exception {
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_PASSWORD_CHANGE.name())) {
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "Password change confirmation",
                    "",
                    SELF_PASSWORD_CHANGE_CONFIRMATION
            );
        }
    }

    public Map<String, String> changePasswordMethodSelection(String method,
                                                             HttpServletRequest request) throws Exception {
        MfaType mfaType = getMfaType(method);
        checkMfaGloballyEnabled(unleash);
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        user.setUsername(request.getHeader(X_USERNAME_HEADER));
        user.setEmail(request.getHeader(X_EMAIL_HEADER));
        user.setMfaEnabled(Boolean.parseBoolean(request.getHeader(X_MFA_ENABLED_HEADER)));
        setMfaMethodsFromHeader(user, request);
        switch (mfaType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return sendEmailOtpToChangePassword(user);
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return sendEmailOtpToChangePassword(user);
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
        throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, String> sendEmailOtpToChangePassword(UserModel user) throws Exception {
        mailService.sendEmailAsync(
                aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                "Otp for password change",
                generateOtpForPasswordChange(user),
                OTP
        );
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    private String generateOtpForPasswordChange(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedPasswordChangeOtpKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedPasswordChangeOtpKey(UserModel user) throws Exception {
        return getEncryptedPasswordChangeOtpKey(user.getId());
    }

    private String getEncryptedPasswordChangeOtpKey(UUID userId) throws Exception {
        return getEncryptedPasswordChangeOtpKey(userId.toString());
    }

    private String getEncryptedPasswordChangeOtpKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX + userId);
    }

    public ResponseEntity<Map<String, Object>> verifyChangePassword(ChangePasswordDto dto,
                                                                    HttpServletRequest request) throws Exception {
        MfaType mfaType = getMfaType(dto.getMethod());
        Set<String> invalidInputs = validateNewAndConfirmNewPassword(dto);
        try {
            validateOtp(dto.getOtpTotp(), 6);
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid Otp/Totp");
        }
        if (!invalidInputs.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        }
        checkMfaGloballyEnabled(unleash);
        UserModel user = new UserModel();
        user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        user.setMfaEnabled(Boolean.parseBoolean(request.getHeader(X_MFA_ENABLED_HEADER)));
        setMfaMethodsFromHeader(user, request);
        switch (mfaType) {
            case EMAIL_MFA -> {
                if (user.getMfaMethods().isEmpty()) {
                    if (!unleash.isEnabled(FORCE_MFA.name())) {
                        throw new SimpleBadRequestException("Email Mfa is not enabled");
                    }
                    return ResponseEntity.ok(verifyEmailOtpToChangePassword(user, dto));
                } else if (user.hasMfaMethod(EMAIL_MFA)) {
                    if (!unleash.isEnabled(MFA_EMAIL.name())) {
                        throw new ServiceUnavailableException("Email Mfa is disabled globally");
                    }
                    return ResponseEntity.ok(verifyEmailOtpToChangePassword(user, dto));
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
                return ResponseEntity.ok(verifyAuthenticatorAppTotpToChangePassword(user, dto));
            }
        }
        throw new SimpleBadRequestException("Unsupported Mfa type: " + dto.getMethod() + ". Supported types: " + MFA_METHODS);
    }

    private Map<String, Object> verifyEmailOtpToChangePassword(UserModel user,
                                                               ChangePasswordDto dto) throws Exception {
        String encryptedPasswordChangeOtpKey = getEncryptedPasswordChangeOtpKey(user);
        String encryptedOtp = redisGet(encryptedPasswordChangeOtpKey, stringRedisTemplate);
        if (encryptedOtp != null) {
            if (aesRandomEncryptorDecryptor.decrypt(encryptedOtp).equals(dto.getOtpTotp())) {
                try {
                    redisDelete(encryptedPasswordChangeOtpKey, stringRedisTemplate);
                } catch (Exception ignored) {
                }
                user = dbServiceClient.getUserById(user.getId());
                if (user == null) {
                    throw new SimpleBadRequestException("Invalid user");
                }
                authServiceClient.revokeTokens(Set.of(user));
                selfChangePassword(user, dto.getNewPassword());
                emailConfirmationOnSelfPasswordChange(user);
                return Map.of("message", "Password changed successfully");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private Map<String, Object> verifyAuthenticatorAppTotpToChangePassword(UserModel user,
                                                                           ChangePasswordDto dto) throws Exception {
        user = dbServiceClient.getUserById(user.getId());
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        if (!verifyTotp(aesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()), dto.getOtpTotp())) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        authServiceClient.revokeTokens(Set.of(user));
        selfChangePassword(user, dto.getNewPassword());
        emailConfirmationOnSelfPasswordChange(user);
        return Map.of("message", "Password changed successfully");
    }

    public Map<String, String> emailChangeRequest(String newEmail,
                                                  HttpServletRequest request) throws Exception {
        if (unleash.isEnabled(EMAIL_CHANGE_ENABLED.name())) {
            validateEmail(newEmail);
            String encryptedNewEmail = aesStaticEncryptorDecryptor.encrypt(newEmail);
            if (request.getHeader(X_EMAIL_HEADER).equals(encryptedNewEmail)) {
                throw new SimpleBadRequestException("New email cannot be same as current email");
            }
            if (dbServiceClient.existsByEmail(encryptedNewEmail)) {
                throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
            }
            String encryptedNormalizedNewEmail = aesStaticEncryptorDecryptor.encrypt(normalizeEmail(newEmail));
            if (!request.getHeader(X_REAL_EMAIL_HEADER).equals(encryptedNormalizedNewEmail)) {
                if (dbServiceClient.existsByRealEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
                }
            }
            if (!request.getHeader(X_EMAILS_FROM_EXTERNAL_IDENTITIES_HEADER).contains(encryptedNormalizedNewEmail)) {
                if (dbServiceClient.externalIdentityExistsByEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
                }
            }
            UserModel user = new UserModel();
            user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
            storeNewEmailForEmailChange(user, newEmail);
            mailService.sendEmailAsync(
                    newEmail,
                    "Otp for email change in new email",
                    generateOtpForEmailChangeForNewEmail(user),
                    OTP
            );
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(request.getHeader(X_EMAIL_HEADER)),
                    "Otp for email change in old email",
                    generateOtpForEmailChangeForOldEmail(user),
                    OTP
            );
            return Map.of("message", "Otp's sent to your new & old email. Please check your emails to verify your email change");
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    private void storeNewEmailForEmailChange(UserModel user,
                                             String newEmail) throws Exception {
        redisSave(
                getEncryptedNewEmailKey(user),
                aesRandomEncryptorDecryptor.encrypt(newEmail),
                stringRedisTemplate
        );
    }

    private String getEncryptedNewEmailKey(UserModel user) throws Exception {
        return getEncryptedNewEmailKey(user.getId());
    }

    private String getEncryptedNewEmailKey(UUID userId) throws Exception {
        return getEncryptedNewEmailKey(userId.toString());
    }

    private String getEncryptedNewEmailKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_STORE_PREFIX + userId);
    }

    private String generateOtpForEmailChangeForNewEmail(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedNewEmailChangeOtpKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedNewEmailChangeOtpKey(UserModel user) throws Exception {
        return getEncryptedNewEmailChangeOtpKey(user.getId());
    }

    private String getEncryptedNewEmailChangeOtpKey(UUID userId) throws Exception {
        return getEncryptedNewEmailChangeOtpKey(userId.toString());
    }

    private String getEncryptedNewEmailChangeOtpKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_CHANGE_OTP_FOR_NEW_EMAIL_PREFIX + userId);
    }

    private String generateOtpForEmailChangeForOldEmail(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedOldEmailChangeOtpKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedOldEmailChangeOtpKey(UserModel user) throws Exception {
        return getEncryptedOldEmailChangeOtpKey(user.getId());
    }

    private String getEncryptedOldEmailChangeOtpKey(UUID userId) throws Exception {
        return getEncryptedOldEmailChangeOtpKey(userId.toString());
    }

    private String getEncryptedOldEmailChangeOtpKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX + userId);
    }

    public Map<String, Object> verifyEmailChange(String newEmailOtp,
                                                 String oldEmailOtp,
                                                 String password,
                                                 HttpServletRequest request) throws Exception {
        if (unleash.isEnabled(EMAIL_CHANGE_ENABLED.name())) {
            try {
                validateOtp(newEmailOtp, 6);
                validateOtp(oldEmailOtp, 6);
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            try {
                validatePassword(password);
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid password");
            }
            UserModel user = new UserModel();
            user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
            user.setEmail(request.getHeader(X_EMAIL_HEADER));
            user.setRealEmail(request.getHeader(X_REAL_EMAIL_HEADER));
            String encryptedNewEmailChangeOtpKey = getEncryptedNewEmailChangeOtpKey(user);
            String encryptedNewEmailOtp = redisGet(encryptedNewEmailChangeOtpKey, stringRedisTemplate);
            if (encryptedNewEmailOtp == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            if (!aesRandomEncryptorDecryptor.decrypt(encryptedNewEmailOtp).equals(newEmailOtp)) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String encryptedOldEmailChangeOtpKey = getEncryptedOldEmailChangeOtpKey(user);
            String encryptedOldEmailOtp = redisGet(encryptedOldEmailChangeOtpKey, stringRedisTemplate);
            if (encryptedOldEmailOtp == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            if (!aesRandomEncryptorDecryptor.decrypt(encryptedOldEmailOtp).equals(oldEmailOtp)) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String encryptedNewEmailKey = getEncryptedNewEmailKey(user);
            String encryptedStoredNewEmail = redisGet(encryptedNewEmailKey, stringRedisTemplate);
            if (encryptedStoredNewEmail == null) {
                throw new SimpleBadRequestException("Invalid Otp's");
            }
            String newEmail = aesRandomEncryptorDecryptor.decrypt(encryptedStoredNewEmail);
            String encryptedNewEmail = aesStaticEncryptorDecryptor.encrypt(newEmail);
            if (user.getEmail().equals(encryptedNewEmail)) {
                throw new SimpleBadRequestException("New email cannot be same as current email");
            }
            if (dbServiceClient.existsByEmail(encryptedNewEmail)) {
                throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
            }
            String encryptedNormalizedNewEmail = aesStaticEncryptorDecryptor.encrypt(normalizeEmail(newEmail));
            if (!user.getRealEmail().equals(encryptedNormalizedNewEmail)) {
                if (dbServiceClient.existsByRealEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
                }
            }
            if (!request.getHeader(X_EMAILS_FROM_EXTERNAL_IDENTITIES_HEADER).contains(encryptedNormalizedNewEmail)) {
                if (dbServiceClient.externalIdentityExistsByEmail(encryptedNormalizedNewEmail)) {
                    throw new SimpleBadRequestException("Email: '" + newEmail + "' is already taken");
                }
            }
            user = dbServiceClient.getUserById(user.getId());
            if (user == null) {
                throw new SimpleBadRequestException("Invalid user");
            }
            checkDeletedStatus(user);
            checkEnabledStatus(user);
            checkLockedStatus(user);
            checkExpiredStatus(user);
            checkCredentialsExpiredStatus(user);
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new SimpleBadRequestException("Invalid password");
            }
            String oldEmail = aesStaticEncryptorDecryptor.decrypt(user.getEmail());
            user.setEmail(encryptedNewEmail);
            user.setRealEmail(encryptedNormalizedNewEmail);
            user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
            authServiceClient.revokeTokens(Set.of(user));
            try {
                redisDeleteAll(
                        Set.of(
                                encryptedNewEmailChangeOtpKey,
                                encryptedOldEmailChangeOtpKey,
                                encryptedNewEmailKey
                        ),
                        stringRedisTemplate
                );
            } catch (Exception ignored) {
            }
            if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_EMAIL_CHANGE.name())) {
                mailService.sendEmailAsync(
                        oldEmail,
                        "Email change confirmation on old email",
                        "",
                        SELF_EMAIL_CHANGE_CONFIRMATION
                );
            }
            return Map.of(
                    "message", "Email change successful. Please login again to continue",
                    "user", mapperUtility.toUserSummaryDto(dbServiceClient.updateUser(user))
            );
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> deleteAccount(String password,
                                                             HttpServletRequest request) throws Exception {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            try {
                validatePassword(password);
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid password");
            }
            UserModel user = new UserModel();
            user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
            user.setMfaEnabled(Boolean.parseBoolean(request.getHeader(X_MFA_ENABLED_HEADER)));
            setMfaMethodsFromHeader(user, request);
            if (unleash.isEnabled(MFA.name())) {
                if (shouldDoMfa(user, unleash)) {
                    return ResponseEntity.ok(Map.of(
                            "message", "Please select a method for account deletion",
                            "methods", user.getMfaMethods())
                    );
                }
                if (unleash.isEnabled(FORCE_MFA.name())) {
                    return ResponseEntity.ok(Map.of(
                            "message", "Please select a method for account deletion",
                            "methods", Set.of(EMAIL_MFA))
                    );
                }
            }
            user = dbServiceClient.getUserById(user.getId());
            if (user == null) {
                throw new SimpleBadRequestException("Invalid user");
            }
            checkDeletedStatus(user);
            checkEnabledStatus(user);
            checkLockedStatus(user);
            checkExpiredStatus(user);
            checkCredentialsExpiredStatus(user);
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new SimpleBadRequestException("Invalid password");
            }
            selfDeleteAccount(user);
            return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private void selfDeleteAccount(UserModel user) throws Exception {
        authServiceClient.revokeTokens(Set.of(user));
        user.recordAccountDeletionStatus(true, aesRandomEncryptorDecryptor.encrypt("SELF"));
        dbServiceClient.updateUser(user);
        if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_ACCOUNT_DELETION.name())) {
            mailService.sendEmailAsync(
                    aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "Account deletion confirmation",
                    "",
                    ACCOUNT_DELETION_CONFIRMATION
            );
        }
    }

    public Map<String, String> deleteAccountMethodSelection(String method,
                                                            HttpServletRequest request) throws Exception {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            MfaType mfaType = getMfaType(method);
            checkMfaGloballyEnabled(unleash);
            UserModel user = new UserModel();
            user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
            user.setEmail(request.getHeader(X_EMAIL_HEADER));
            setMfaMethodsFromHeader(user, request);
            switch (mfaType) {
                case EMAIL_MFA -> {
                    if (user.getMfaMethods().isEmpty()) {
                        if (!unleash.isEnabled(FORCE_MFA.name())) {
                            throw new SimpleBadRequestException("Email Mfa is not enabled");
                        }
                        return sendEmailOtpToDeleteAccount(user);
                    } else if (user.hasMfaMethod(EMAIL_MFA)) {
                        if (!unleash.isEnabled(MFA_EMAIL.name())) {
                            throw new ServiceUnavailableException("Email Mfa is disabled globally");
                        }
                        return sendEmailOtpToDeleteAccount(user);
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
            throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private Map<String, String> sendEmailOtpToDeleteAccount(UserModel user) throws Exception {
        mailService.sendEmailAsync(
                aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                "Otp for account deletion",
                generateEmailOtpForAccountDeletion(user),
                OTP
        );
        return Map.of("message", "Otp sent to your registered email address. Please check your email to continue");
    }

    private String generateEmailOtpForAccountDeletion(UserModel user) throws Exception {
        String otp = generateOtp();
        redisSave(
                getEncryptedEmailOtpToDeleteAccountKey(user),
                aesRandomEncryptorDecryptor.encrypt(otp),
                stringRedisTemplate
        );
        return otp;
    }

    private String getEncryptedEmailOtpToDeleteAccountKey(UserModel user) throws Exception {
        return getEncryptedEmailOtpToDeleteAccountKey(user.getId());
    }

    private String getEncryptedEmailOtpToDeleteAccountKey(UUID userId) throws Exception {
        return getEncryptedEmailOtpToDeleteAccountKey(userId.toString());
    }

    private String getEncryptedEmailOtpToDeleteAccountKey(String userId) throws Exception {
        return aesStaticEncryptorDecryptor.encrypt(EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX + userId);
    }

    public Map<String, String> verifyDeleteAccount(String otpTotp,
                                                   String method,
                                                   HttpServletRequest request) throws Exception {
        if (unleash.isEnabled(ACCOUNT_DELETION_ALLOWED.name())) {
            MfaType mfaType = getMfaType(method);
            try {
                validateOtp(otpTotp, 6);
            } catch (SimpleBadRequestException ex) {
                throw new SimpleBadRequestException("Invalid Otp/Totp");
            }
            checkMfaGloballyEnabled(unleash);
            UserModel user = new UserModel();
            user.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
            setMfaMethodsFromHeader(user, request);
            switch (mfaType) {
                case EMAIL_MFA -> {
                    if (user.getMfaMethods().isEmpty()) {
                        if (!unleash.isEnabled(FORCE_MFA.name())) {
                            throw new SimpleBadRequestException("Email Mfa is not enabled");
                        }
                        return verifyEmailOtpToDeleteAccount(otpTotp, user);
                    } else if (user.hasMfaMethod(EMAIL_MFA)) {
                        if (!unleash.isEnabled(MFA_EMAIL.name())) {
                            throw new ServiceUnavailableException("Email Mfa is disabled globally");
                        }
                        return verifyEmailOtpToDeleteAccount(otpTotp, user);
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
                    return verifyAuthenticatorAppTOTPToDeleteAccount(otpTotp, user);
                }
            }
            throw new SimpleBadRequestException("Unsupported Mfa type: " + method + ". Supported types: " + MFA_METHODS);
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private Map<String, String> verifyEmailOtpToDeleteAccount(String otp,
                                                              UserModel user) throws Exception {
        String encryptedEmailOtpToDeleteAccountKey = getEncryptedEmailOtpToDeleteAccountKey(user);
        String encryptedOtp = redisGet(encryptedEmailOtpToDeleteAccountKey, stringRedisTemplate);
        if (encryptedOtp != null) {
            if (aesRandomEncryptorDecryptor.decrypt(encryptedOtp).equals(otp)) {
                try {
                    redisDelete(encryptedEmailOtpToDeleteAccountKey, stringRedisTemplate);
                } catch (Exception ignored) {
                }
                user = dbServiceClient.getUserById(user.getId());
                if (user == null) {
                    throw new SimpleBadRequestException("Invalid user");
                }
                checkDeletedStatus(user);
                checkEnabledStatus(user);
                checkLockedStatus(user);
                checkExpiredStatus(user);
                checkCredentialsExpiredStatus(user);
                selfDeleteAccount(user);
                return Map.of("message", "Account deleted successfully");
            }
            throw new SimpleBadRequestException("Invalid Otp");
        }
        throw new SimpleBadRequestException("Invalid Otp");
    }

    private Map<String, String> verifyAuthenticatorAppTOTPToDeleteAccount(String totp,
                                                                          UserModel user) throws Exception {
        user = dbServiceClient.getUserById(user.getId());
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        if (!verifyTotp(aesRandomEncryptorDecryptor.decrypt(user.getAuthAppSecret()), totp)) {
            throw new SimpleBadRequestException("Invalid Totp");
        }
        checkDeletedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
        selfDeleteAccount(user);
        return Map.of("message", "Account deleted successfully");
    }

    public ResponseEntity<Map<String, Object>> updateDetails(SelfUpdationDto dto,
                                                             HttpServletRequest request) throws Exception {
        UserModel user = dbServiceClient.getUserById(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        if (user == null) {
            throw new SimpleBadRequestException("Invalid user");
        }
        checkDeletedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
        SelfUpdationResultDto selfUpdationResult = validateAndSet(user, dto);
        if (!selfUpdationResult.getInvalidInputs().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", selfUpdationResult.getInvalidInputs()));
        }
        if (selfUpdationResult.isModified()) {
            user.recordUpdation(aesRandomEncryptorDecryptor.encrypt("SELF"));
            if (unleash.isEnabled(EMAIL_CONFIRMATION_ON_SELF_UPDATE_DETAILS.name())) {
                mailService.sendEmailAsync(
                        aesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                        "Account details updated confirmation",
                        "",
                        SELF_UPDATE_DETAILS_CONFIRMATION
                );
            }
            Map<String, Object> response = new HashMap<>();
            if (selfUpdationResult.isShouldRemoveTokens()) {
                authServiceClient.revokeTokens(Set.of(user));
                response.put("message", "User details updated successfully. Please login again to continue");
            } else {
                response.put("message", "User details updated successfully");
            }
            response.put("user", mapperUtility.toUserSummaryDto(dbServiceClient.updateUser(user)));
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.ok(Map.of("message", "No details were updated"));
    }

    private SelfUpdationResultDto validateAndSet(UserModel user,
                                                 SelfUpdationDto dto) throws Exception {
        boolean isModified = false;
        boolean shouldRemoveTokens = false;
        Set<String> invalidInputs = new HashSet<>();
        try {
            validatePassword(dto.getOldPassword());
            if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
                invalidInputs.add("Invalid old password");
            }
        } catch (SimpleBadRequestException ex) {
            invalidInputs.add("Invalid old password");
        }
        if (dto.getFirstName() != null && !dto.getFirstName().equals(user.getFirstName())) {
            try {
                validateFirstName(dto.getFirstName());
                user.setFirstName(dto.getFirstName());
                isModified = true;
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(ex.getMessage());
            }
        }
        if (dto.getMiddleName() != null && !dto.getMiddleName().equals(user.getMiddleName())) {
            try {
                validateMiddleName(dto.getMiddleName());
                user.setMiddleName(dto.getMiddleName());
                isModified = true;
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(ex.getMessage());
            }
        }
        if (dto.getLastName() != null && !dto.getLastName().equals(user.getLastName())) {
            try {
                validateLastName(dto.getLastName());
                user.setLastName(dto.getLastName());
                isModified = true;
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(ex.getMessage());
            }
        }
        if (dto.getUsername() != null && !dto.getUsername().equals(aesStaticEncryptorDecryptor.decrypt(user.getUsername()))) {
            try {
                validateUsername(dto.getUsername());
                String encryptedUsername = aesStaticEncryptorDecryptor.encrypt(dto.getUsername());
                if (dbServiceClient.existsByUsername(encryptedUsername)) {
                    invalidInputs.add("Username already taken");
                } else {
                    user.setUsername(encryptedUsername);
                    isModified = true;
                    shouldRemoveTokens = true;
                }
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(ex.getMessage());
            }
        }
        return new SelfUpdationResultDto(isModified, shouldRemoveTokens, invalidInputs);
    }
}
