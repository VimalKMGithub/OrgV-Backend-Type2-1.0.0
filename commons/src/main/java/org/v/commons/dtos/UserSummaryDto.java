package org.v.commons.dtos;

import lombok.Getter;
import lombok.Setter;
import org.v.commons.enums.MfaType;
import org.v.commons.models.ExternalIdentityModel;
import org.v.commons.models.RoleModel;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
public class UserSummaryDto {
    private UUID id;
    private String firstName;
    private String middleName;
    private String lastName;
    private String username;
    private String email;
    private String createdBy;
    private String updatedBy;
    private Set<RoleModel> roles;
    private Set<MfaType> mfaMethods;
    private Instant lastLoginAt;
    private Instant passwordChangedAt;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant lastLockedAt;
    private boolean emailVerified;
    private boolean mfaEnabled;
    private boolean accountLocked;
    private boolean accountEnabled;
    private int failedLoginAttempts;
    private int failedMfaAttempts;
    private int allowedConcurrentLogins;
    private boolean oauth2User;
    private Set<ExternalIdentityModel> externalIdentities;
}
