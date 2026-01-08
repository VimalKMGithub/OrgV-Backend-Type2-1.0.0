package org.v.commons.models;

import lombok.*;
import org.v.commons.enums.MfaType;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserModel {
    private UUID id;
    private String firstName;
    private String middleName;
    private String lastName;
    private String username;
    private String password;
    private String email;
    private String realEmail;
    @Builder.Default
    private boolean emailVerified = false;
    @Builder.Default
    private boolean mfaEnabled = false;
    @Builder.Default
    private boolean accountLocked = false;
    @Builder.Default
    private boolean accountEnabled = true;
    @Builder.Default
    private boolean accountDeleted = false;
    private Instant accountDeletedAt;
    private String accountDeletedBy;
    private Instant accountRecoveredAt;
    private String accountRecoveredBy;
    private String authAppSecret;

    public void recordAccountDeletionStatus(boolean isDeleted,
                                            String agentUsername) {
        if (isDeleted) {
            this.accountDeleted = true;
            this.accountDeletedAt = Instant.now();
            this.accountDeletedBy = agentUsername;
        } else {
            this.accountDeleted = false;
            this.accountRecoveredAt = Instant.now();
            this.accountRecoveredBy = agentUsername;
        }
    }

    private Set<RoleModel> roles;
    private Instant loginAt;
    private Instant lockedAt;

    public void recordLockedStatus(boolean locked) {
        this.accountLocked = locked;
        this.lockedAt = locked ? Instant.now() : null;
        if (!locked) {
            this.failedLoginAttempts = 0;
            this.failedMfaAttempts = 0;
        }
    }

    @Builder.Default
    private int failedLoginAttempts = 0;
    @Builder.Default
    private int failedMfaAttempts = 0;
    @Builder.Default
    private int allowedConcurrentLogins = 1;
    private Instant passwordChangedAt;

    public void recordPasswordChange(String newPassword) {
        this.password = newPassword;
        this.passwordChangedAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
    }

    private Instant createdAt;
    private Instant updatedAt;
    private String createdBy;
    private String updatedBy;

    public void recordUpdation(String updater) {
        this.updatedAt = Instant.now();
        this.updatedBy = updater;
    }

    public void recordSuccessfulLogin() {
        this.loginAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
        this.accountLocked = false;
    }

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int UPPER_MAX_FAILED_ATTEMPTS = 10;
    private static final int MAX_FAILED_MFA_ATTEMPTS = 3;
    private static final int UPPER_MAX_FAILED_MFA_ATTEMPTS = 5;

    public void recordFailedLoginAttempt() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
            this.accountLocked = true;
            this.lockedAt = Instant.now();
        }
        if (this.failedLoginAttempts >= UPPER_MAX_FAILED_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    public void recordFailedMfaAttempt() {
        this.failedMfaAttempts++;
        if (this.failedMfaAttempts >= MAX_FAILED_MFA_ATTEMPTS) {
            this.accountLocked = true;
            this.lockedAt = Instant.now();
        }
        if (this.failedMfaAttempts >= UPPER_MAX_FAILED_MFA_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    private Set<MfaType> mfaMethods;

    public void addMfaMethod(MfaType method) {
        this.mfaMethods.add(method);
        this.mfaEnabled = true;
    }

    public void removeMfaMethod(MfaType method) {
        this.mfaMethods.remove(method);
        this.mfaEnabled = !this.mfaMethods.isEmpty();
    }

    public boolean hasMfaMethod(MfaType method) {
        return this.mfaMethods.contains(method);
    }

    @Builder.Default
    private boolean oauth2User = false;
    private Set<ExternalIdentityModel> externalIdentities;
}
