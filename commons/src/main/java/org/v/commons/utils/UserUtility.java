package org.v.commons.utils;

import org.v.commons.clients.DbServiceClient;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.enums.MfaType;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.models.UserModel;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.v.commons.utils.ValidationUtility.*;

public class UserUtility {
    public static UserModel getUserByUsernameOrEmailOrId(String usernameOrEmailOrId,
                                                         DbServiceClient dbServiceClient,
                                                         AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor) throws Exception {
        UserModel user;
        if (UUID_PATTERN.matcher(usernameOrEmailOrId).matches()) {
            user = dbServiceClient.getUserById(UUID.fromString(usernameOrEmailOrId));
        } else if (EMAIL_PATTERN.matcher(usernameOrEmailOrId).matches()) {
            user = dbServiceClient.getUserByEmail(aesStaticEncryptorDecryptor.encrypt(usernameOrEmailOrId));
        } else if (USERNAME_PATTERN.matcher(usernameOrEmailOrId).matches()) {
            user = dbServiceClient.getUserByUsername(aesStaticEncryptorDecryptor.encrypt(usernameOrEmailOrId));
        } else {
            throw new SimpleBadRequestException("Invalid user identifier");
        }
        if (user == null) {
            throw new SimpleBadRequestException("User not found");
        }
        return user;
    }

    public static void checkUserStatus(UserModel user) {
        checkDeletedStatus(user);
        checkEmailVerifiedStatus(user);
        checkEnabledStatus(user);
        checkLockedStatus(user);
        checkExpiredStatus(user);
        checkCredentialsExpiredStatus(user);
    }

    public static void checkDeletedStatus(UserModel user) {
        if (user.isAccountDeleted()) {
            throw new SimpleBadRequestException("User not found");
        }
    }

    public static void checkEmailVerifiedStatus(UserModel user) {
        if (!user.isEmailVerified()) {
            throw new SimpleBadRequestException("Please verify your email");
        }
    }

    public static void checkEnabledStatus(UserModel user) {
        if (!user.isAccountEnabled()) {
            throw new SimpleBadRequestException("Account is disabled. Please contact support.");
        }
    }

    public static void checkLockedStatus(UserModel user) {
        if (user.isAccountLocked() && user.getLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now())) {
            throw new SimpleBadRequestException("Account is temporarily locked. Please try again later.");
        }
    }

    public static void checkExpiredStatus(UserModel user) {
        if (user.getCreatedAt().plus(36500, ChronoUnit.DAYS).isBefore(Instant.now())) {
            throw new SimpleBadRequestException("Account has expired. Please contact support.");
        }
    }

    public static void checkCredentialsExpiredStatus(UserModel user) {
        if (user.getPasswordChangedAt().plus(365, ChronoUnit.DAYS).isBefore(Instant.now())) {
            throw new SimpleBadRequestException("Credentials have expired. Please reset your password.");
        }
    }

    public static void setMfaMethodsFromHeader(UserModel user,
                                               String mfaMethodsHeader) {
        Set<MfaType> mfaMethods = new HashSet<>();
        for (String method : Set.of(mfaMethodsHeader.split(","))) {
            if (!method.isBlank()) {
                mfaMethods.add(MfaType.valueOf(method));
            }
        }
        user.setMfaMethods(mfaMethods);
    }
}
