package org.v.commons.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.v.commons.dtos.RoleSummaryDto;
import org.v.commons.dtos.UserSummaryDto;
import org.v.commons.dtos.UserSummaryToCompanyUsersDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.models.ExternalIdentityModel;
import org.v.commons.models.PermissionModel;
import org.v.commons.models.RoleModel;
import org.v.commons.models.UserModel;

@Component
@RequiredArgsConstructor
public class MapperUtility {
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;

    public UserSummaryDto toUserSummaryDto(UserModel user) throws Exception {
        UserSummaryDto dto = new UserSummaryDto();
        mapCommonFields(user, dto);
        return dto;
    }

    private void mapCommonFields(UserModel user,
                                 UserSummaryDto dto) throws Exception {
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setMiddleName(user.getMiddleName());
        dto.setLastName(user.getLastName());
        dto.setUsername(aesStaticEncryptorDecryptor.decrypt(user.getUsername()));
        dto.setEmail(aesStaticEncryptorDecryptor.decrypt(user.getEmail()));
        dto.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(user.getCreatedBy()));
        dto.setUpdatedBy(user.getUpdatedBy() == null ? null : aesRandomEncryptorDecryptor.decrypt(user.getUpdatedBy()));
        if (user.getRoles() != null) {
            for (RoleModel role : user.getRoles()) {
                role.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(role.getCreatedBy()));
                role.setUpdatedBy(role.getUpdatedBy() == null ? null : aesRandomEncryptorDecryptor.decrypt(role.getUpdatedBy()));
                if (role.getPermissions() != null) {
                    for (PermissionModel permission : role.getPermissions()) {
                        permission.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(permission.getCreatedBy()));
                    }
                }
            }
        }
        dto.setRoles(user.getRoles());
        dto.setMfaEnabled(user.isMfaEnabled());
        dto.setMfaMethods(user.getMfaMethods());
        dto.setLastLoginAt(user.getLoginAt());
        dto.setPasswordChangedAt(user.getPasswordChangedAt());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        dto.setLastLockedAt(user.getLockedAt());
        dto.setEmailVerified(user.isEmailVerified());
        dto.setAccountLocked(user.isAccountLocked());
        dto.setAccountEnabled(user.isAccountEnabled());
        dto.setFailedLoginAttempts(user.getFailedLoginAttempts());
        dto.setFailedMfaAttempts(user.getFailedMfaAttempts());
        dto.setAllowedConcurrentLogins(user.getAllowedConcurrentLogins());
        dto.setOauth2User(user.isOauth2User());
        if (user.getExternalIdentities() != null) {
            for (ExternalIdentityModel externalIdentity : user.getExternalIdentities()) {
                externalIdentity.setProvider(aesStaticEncryptorDecryptor.decrypt(externalIdentity.getProvider()));
                externalIdentity.setProviderUserId(aesStaticEncryptorDecryptor.decrypt(externalIdentity.getProviderUserId()));
                externalIdentity.setEmail(aesStaticEncryptorDecryptor.decrypt(externalIdentity.getEmail()));
                externalIdentity.setProfilePictureUrl(aesRandomEncryptorDecryptor.decrypt(externalIdentity.getProfilePictureUrl()));
            }
        }
        dto.setExternalIdentities(user.getExternalIdentities());
    }

    public UserSummaryToCompanyUsersDto toUserSummaryToCompanyUsersDto(UserModel user) throws Exception {
        UserSummaryToCompanyUsersDto dto = new UserSummaryToCompanyUsersDto();
        mapCommonFields(user, dto);
        dto.setRealEmail(aesStaticEncryptorDecryptor.decrypt(user.getRealEmail()));
        dto.setAccountDeleted(user.isAccountDeleted());
        dto.setAccountDeletedAt(user.getAccountDeletedAt());
        dto.setAccountDeletedBy(user.getAccountDeletedBy() == null ? null : aesRandomEncryptorDecryptor.decrypt(user.getAccountDeletedBy()));
        dto.setAccountRecoveredAt(user.getAccountRecoveredAt());
        dto.setAccountRecoveredBy(user.getAccountRecoveredBy() == null ? null : aesRandomEncryptorDecryptor.decrypt(user.getAccountRecoveredBy()));
        return dto;
    }

    public RoleSummaryDto toRoleSummaryDto(RoleModel role) throws Exception {
        RoleSummaryDto dto = new RoleSummaryDto();
        dto.setRoleName(role.getRoleName());
        dto.setDescription(role.getDescription());
        dto.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(role.getCreatedBy()));
        dto.setUpdatedBy(role.getUpdatedBy() == null ? null : aesRandomEncryptorDecryptor.decrypt(role.getUpdatedBy()));
        if (role.getPermissions() != null) {
            for (PermissionModel permission : role.getPermissions()) {
                permission.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(permission.getCreatedBy()));
            }
        }
        dto.setPermissions(role.getPermissions());
        dto.setCreatedAt(role.getCreatedAt());
        dto.setUpdatedAt(role.getUpdatedAt());
        dto.setSystemRole(role.isSystemRole());
        return dto;
    }
}
