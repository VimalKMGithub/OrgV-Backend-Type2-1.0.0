package org.v.admin.service.services;

import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.v.admin.service.dtos.*;
import org.v.commons.clients.AuthServiceClient;
import org.v.commons.clients.DbServiceClient;
import org.v.commons.dtos.RoleSummaryDto;
import org.v.commons.dtos.UserSummaryToCompanyUsersDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.exceptions.ServiceUnavailableException;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.models.PermissionModel;
import org.v.commons.models.RoleModel;
import org.v.commons.models.UserModel;
import org.v.commons.utils.MapperUtility;

import java.time.Instant;
import java.util.*;

import static org.v.commons.constants.HeadersCookies.*;
import static org.v.commons.enums.FeatureFlags.*;
import static org.v.commons.enums.SystemRoles.ROLE_PRIORITY_MAP;
import static org.v.commons.enums.SystemRoles.TOP_ROLES;
import static org.v.commons.utils.PreAuthorizationUtility.*;
import static org.v.commons.utils.ToggleUtility.TOGGLE_TYPES;
import static org.v.commons.utils.ToggleUtility.isToggleExists;
import static org.v.commons.utils.ValidationUtility.*;

@Service
@RequiredArgsConstructor
public class AdminService {
    private static final int DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_READ_AT_A_TIME = 300;
    private static final int DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_CREATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_DELETE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_ROLES_TO_READ_AT_A_TIME = 300;
    private static final int DEFAULT_MAX_ROLES_TO_UPDATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_PERMISSIONS_TO_READ_AT_A_TIME = 300;
    private final DbServiceClient dbServiceClient;
    private final AuthServiceClient authServiceClient;
    private final Unleash unleash;
    private final MapperUtility mapperUtility;
    private final PasswordEncoder passwordEncoder;
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;

    public ResponseEntity<Map<String, Object>> createUsers(Set<UserCreationDto> dtos,
                                                           String leniency,
                                                           HttpServletRequest request) throws Exception {
        Set<String> creatorAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canCreateUsers(creatorAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String creatorHighestTopRole = getUserHighestTopRole(creatorAuthorities);
        Variant variant = unleash.getVariant(ALLOW_CREATE_USERS.name());
        if (entryCheck(variant, creatorHighestTopRole)) {
            checkUserCanCreateUsers(creatorHighestTopRole);
            validateDtosSizeForUsersCreation(variant, dtos);
            ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult = validateInputsForUsersCreation(dtos, creatorHighestTopRole);
            Map<String, Object> mapOfErrors = errorsStuffingIfAny(validateInputsForUsersCreationResult);
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (dtos.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No users created"));
                }
            } else if (dtos.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users created",
                            "reasons_due_to_which_users_has_not_been_created", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No users created"));
            }
            AlreadyTakenUsernamesAndEmailsResultDto alreadyTakenUsernamesAndEmailsResult = getAlreadyTakenUsernamesAndEmails(validateInputsForUsersCreationResult);
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().isEmpty()) {
                mapOfErrors.put("already_taken_usernames", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames());
            }
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().isEmpty()) {
                mapOfErrors.put("already_taken_emails", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            Map<String, RoleModel> resolvedRolesMap = resolveRoles(validateInputsForUsersCreationResult.getRoles());
            if (!validateInputsForUsersCreationResult.getRoles().isEmpty()) {
                mapOfErrors.put("missing_roles", validateInputsForUsersCreationResult.getRoles());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            Set<UserModel> newUsers = new HashSet<>();
            String decryptedCreatorUsername = aesStaticEncryptorDecryptor.decrypt(request.getHeader(X_USERNAME_HEADER));
            for (UserCreationDto dto : dtos) {
                if (isLenient) {
                    if (alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().contains(dto.getUsername())
                            || alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().contains(dto.getEmail())) {
                        continue;
                    }
                }
                if (dto.getRoles() == null || dto.getRoles().isEmpty()) {
                    newUsers.add(toUserModel(
                                    dto,
                                    new HashSet<>(),
                                    decryptedCreatorUsername,
                                    validateInputsForUsersCreationResult.getUsernameToEncryptedUsernameMap(),
                                    validateInputsForUsersCreationResult.getEmailToEncryptedEmailMap()
                            )
                    );
                } else {
                    Set<RoleModel> rolesToAssign = new HashSet<>();
                    for (String roleName : dto.getRoles()) {
                        RoleModel role = resolvedRolesMap.get(roleName);
                        if (role != null) {
                            rolesToAssign.add(role);
                        }
                    }
                    newUsers.add(toUserModel(
                                    dto,
                                    rolesToAssign,
                                    decryptedCreatorUsername,
                                    validateInputsForUsersCreationResult.getUsernameToEncryptedUsernameMap(),
                                    validateInputsForUsersCreationResult.getEmailToEncryptedEmailMap()
                            )
                    );
                }
            }
            mapOfErrors.remove("missing_roles");
            if (newUsers.isEmpty()) {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users created",
                            "reasons_due_to_which_users_has_not_been_created", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No users created"));
            }
            List<UserSummaryToCompanyUsersDto> users = new ArrayList<>();
            for (UserModel userModel : dbServiceClient.createUsers(newUsers)) {
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            if (isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "created_users", users,
                        "reasons_due_to_which_some_users_has_not_been_created", mapOfErrors
                ));
            }
            return ResponseEntity.ok(Map.of("created_users", users));
        }
        throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    private boolean validateLeniency(String leniency) {
        if (!isToggleExists(leniency)) {
            throw new SimpleBadRequestException("Unsupported leniency type: " + leniency + ". Supported values: " + TOGGLE_TYPES);
        }
        return leniency.equalsIgnoreCase("enable");
    }

    private String getUserHighestTopRole(Set<String> userAuthorities) {
        String topRole = null;
        int max = Integer.MAX_VALUE;
        Integer pr;
        for (String authority : userAuthorities) {
            pr = ROLE_PRIORITY_MAP.get(authority);
            if (pr != null && pr < max) {
                max = pr;
                topRole = authority;
            }
        }
        return topRole;
    }

    private boolean entryCheck(Variant variant,
                               String userHighestTopRole) {
        return variant.isEnabled() || TOP_ROLES.getFirst().equals(userHighestTopRole);
    }

    private void checkUserCanCreateUsers(String userHighestTopPermission) {
        if (userHighestTopPermission == null && !unleash.isEnabled(ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name())) {
            throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
        }
    }

    private void validateDtosSizeForUsersCreation(Variant variant,
                                                  Set<UserCreationDto> dtos) {
        if (dtos.isEmpty()) {
            throw new SimpleBadRequestException("No users to create");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToCreateAtATime < 1) {
                maxUsersToCreateAtATime = DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME;
            }
            if (dtos.size() > maxUsersToCreateAtATime) {
                throw new SimpleBadRequestException("Cannot create more than " + maxUsersToCreateAtATime + " users at a time");
            }
        } else if (dtos.size() > DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot create more than " + DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME + " users at a time");
        }
    }

    private ValidateInputsForUsersCreationResultDto validateInputsForUsersCreation(Set<UserCreationDto> dtos,
                                                                                   String creatorHighestTopRole) throws Exception {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        Set<String> encryptedUsernames = new HashSet<>();
        Map<String, String> encryptedUsernameToUsernameMap = new HashMap<>();
        Map<String, String> usernameToEncryptedUsernameMap = new HashMap<>();
        Set<String> emails = new HashSet<>();
        Set<String> encryptedEmails = new HashSet<>();
        Map<String, String> encryptedEmailToEmailMap = new HashMap<>();
        Map<String, String> emailToEncryptedEmailMap = new HashMap<>();
        Set<String> duplicateUsernamesInDtos = new HashSet<>();
        Set<String> duplicateEmailsInDtos = new HashSet<>();
        Set<String> roles = new HashSet<>();
        Set<String> restrictedRoles = new HashSet<>();
        dtos.remove(null);
        Iterator<UserCreationDto> iterator = dtos.iterator();
        Set<String> tempSet;
        UserCreationDto tempDto;
        boolean removeFromDtos;
        boolean removeFromDtosSanitizeRoles;
        String tempStr;
        while (iterator.hasNext()) {
            removeFromDtos = false;
            removeFromDtosSanitizeRoles = false;
            tempDto = iterator.next();
            tempSet = validateRegistrationInputs(tempDto);
            if (tempDto.getAllowedConcurrentLogins() < 1) {
                tempSet.add("Allowed concurrent logins must be at least 1");
            }
            if (!tempSet.isEmpty()) {
                invalidInputs.addAll(tempSet);
                removeFromDtos = true;
            }
            if (tempDto.getUsername() != null && USERNAME_PATTERN.matcher(tempDto.getUsername()).matches()) {
                if (usernames.add(tempDto.getUsername())) {
                    tempStr = aesStaticEncryptorDecryptor.encrypt(tempDto.getUsername());
                    encryptedUsernames.add(tempStr);
                    encryptedUsernameToUsernameMap.put(
                            tempStr,
                            tempDto.getUsername()
                    );
                    usernameToEncryptedUsernameMap.put(
                            tempDto.getUsername(),
                            tempStr
                    );
                } else {
                    duplicateUsernamesInDtos.add(tempDto.getUsername());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getEmail() != null && EMAIL_PATTERN.matcher(tempDto.getEmail()).matches()) {
                if (emails.add(tempDto.getEmail())) {
                    tempStr = aesStaticEncryptorDecryptor.encrypt(tempDto.getEmail());
                    encryptedEmails.add(tempStr);
                    encryptedEmailToEmailMap.put(
                            tempStr,
                            tempDto.getEmail()
                    );
                    emailToEncryptedEmailMap.put(
                            tempDto.getEmail(),
                            tempStr
                    );
                } else {
                    duplicateEmailsInDtos.add(tempDto.getEmail());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getRoles() != null && !tempDto.getRoles().isEmpty()) {
                removeFromDtosSanitizeRoles = sanitizeRoles(tempDto.getRoles(), restrictedRoles, creatorHighestTopRole, roles);
            }
            if (removeFromDtos || removeFromDtosSanitizeRoles) {
                iterator.remove();
            }
        }
        return new ValidateInputsForUsersCreationResultDto(
                invalidInputs,
                encryptedUsernames,
                encryptedUsernameToUsernameMap,
                usernameToEncryptedUsernameMap,
                encryptedEmails,
                encryptedEmailToEmailMap,
                emailToEncryptedEmailMap,
                duplicateUsernamesInDtos,
                duplicateEmailsInDtos,
                roles,
                restrictedRoles
        );
    }

    private boolean sanitizeRoles(Set<String> roles,
                                  Set<String> restrictedRoles,
                                  String userHighestTopRole,
                                  Set<String> rolesCollector) {
        roles.remove(null);
        Iterator<String> iterator = roles.iterator();
        boolean removeFromDtos = false;
        String temp;
        while (iterator.hasNext()) {
            temp = iterator.next();
            if (temp.isBlank()) {
                iterator.remove();
            } else {
                rolesCollector.add(temp);
                removeFromDtos = validateRoleRestriction(temp, restrictedRoles, userHighestTopRole) || removeFromDtos;
            }
        }
        return removeFromDtos;
    }

    private boolean validateRoleRestriction(String role,
                                            Set<String> restrictedRoles,
                                            String userHighestTopRole) {
        boolean isRestricted = false;
        if (!TOP_ROLES.getFirst().equals(userHighestTopRole) && ROLE_PRIORITY_MAP.containsKey(role)) {
            if (userHighestTopRole == null || ROLE_PRIORITY_MAP.get(role) <= ROLE_PRIORITY_MAP.get(userHighestTopRole)) {
                restrictedRoles.add(role);
                isRestricted = true;
            }
        }
        return isRestricted;
    }

    private Map<String, Object> errorsStuffingIfAny(ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult) {
        Map<String, Object> mapOfErrors = new HashMap<>();
        if (!validateInputsForUsersCreationResult.getInvalidInputs().isEmpty()) {
            mapOfErrors.put("invalid_inputs", validateInputsForUsersCreationResult.getInvalidInputs());
        }
        if (!validateInputsForUsersCreationResult.getDuplicateUsernamesInDtos().isEmpty()) {
            mapOfErrors.put("duplicate_usernames_in_request", validateInputsForUsersCreationResult.getDuplicateUsernamesInDtos());
        }
        if (!validateInputsForUsersCreationResult.getDuplicateEmailsInDtos().isEmpty()) {
            mapOfErrors.put("duplicate_emails_in_request", validateInputsForUsersCreationResult.getDuplicateEmailsInDtos());
        }
        if (!validateInputsForUsersCreationResult.getRestrictedRoles().isEmpty()) {
            mapOfErrors.put("not_allowed_to_assign_roles", validateInputsForUsersCreationResult.getRestrictedRoles());
        }
        return mapOfErrors;
    }

    private AlreadyTakenUsernamesAndEmailsResultDto getAlreadyTakenUsernamesAndEmails(ValidateInputsForUsersCreationResultDto validateInputsForUsersCreationResult) {
        Set<String> alreadyTakenUsernames = new HashSet<>();
        for (UserModel user : dbServiceClient.getUsersByUsernameIn(validateInputsForUsersCreationResult.getEncryptedUsernames())) {
            alreadyTakenUsernames.add(validateInputsForUsersCreationResult.getEncryptedUsernameToUsernameMap().get(user.getUsername()));
        }
        Set<String> alreadyTakenEmails = new HashSet<>();
        for (UserModel user : dbServiceClient.getUsersByEmailIn(validateInputsForUsersCreationResult.getEncryptedEmails())) {
            alreadyTakenEmails.add(validateInputsForUsersCreationResult.getEncryptedEmailToEmailMap().get(user.getEmail()));
        }
        return new AlreadyTakenUsernamesAndEmailsResultDto(alreadyTakenUsernames, alreadyTakenEmails);
    }

    private Map<String, RoleModel> resolveRoles(Set<String> roles) {
        if (roles.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, RoleModel> resolvedRolesMap = new HashMap<>();
        for (RoleModel role : dbServiceClient.getRolesByIdIn(roles)) {
            roles.remove(role.getRoleName());
            resolvedRolesMap.put(role.getRoleName(), role);
        }
        return resolvedRolesMap;
    }

    private UserModel toUserModel(UserCreationDto dto,
                                  Set<RoleModel> roles,
                                  String decryptedCreatorUsername,
                                  Map<String, String> usernameToEncryptedUsernameMap,
                                  Map<String, String> emailToEncryptedEmailMap) throws Exception {
        String encryptedEmail = emailToEncryptedEmailMap.get(dto.getEmail());
        return UserModel.builder()
                .username(usernameToEncryptedUsernameMap.get(dto.getUsername()))
                .email(encryptedEmail)
                .realEmail(encryptedEmail)
                .password(passwordEncoder.encode(dto.getPassword()))
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .roles(roles)
                .allowedConcurrentLogins(dto.getAllowedConcurrentLogins())
                .emailVerified(dto.isEmailVerified())
                .accountEnabled(dto.isAccountEnabled())
                .accountLocked(dto.isAccountLocked())
                .lockedAt(dto.isAccountLocked() ? Instant.now() : null)
                .createdBy(aesRandomEncryptorDecryptor.encrypt(decryptedCreatorUsername))
                .accountDeleted(dto.isAccountDeleted())
                .accountDeletedAt(dto.isAccountDeleted() ? Instant.now() : null)
                .accountDeletedBy(dto.isAccountDeleted() ? aesRandomEncryptorDecryptor.encrypt(decryptedCreatorUsername) : null)
                .build();
    }

    public ResponseEntity<Map<String, Object>> deleteUsers(Set<String> usernamesOrEmailsOrIds,
                                                           String hard,
                                                           String leniency,
                                                           HttpServletRequest request) throws Exception {
        Set<String> deleterAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canDeleteUsers(deleterAuthorities);
        boolean hardDelete = validateHardDeletion(hard, "hard");
        boolean isLenient = validateLeniency(leniency);
        String deleterHighestTopRole = getUserHighestTopRole(deleterAuthorities);
        if (hardDelete) {
            if (unleash.isEnabled(ALLOW_HARD_DELETE_USERS.name()) || TOP_ROLES.getFirst().equals(deleterHighestTopRole)) {
                checkUserCanHardDeleteUsers(deleterHighestTopRole);
            } else {
                throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
            }
        }
        UserModel deleter = new UserModel();
        deleter.setId(UUID.fromString(request.getHeader(X_USER_ID_HEADER)));
        deleter.setUsername(request.getHeader(X_USERNAME_HEADER));
        deleter.setEmail(request.getHeader(X_EMAIL_HEADER));
        ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsersResult = validateInputsForDeleteUsers(usernamesOrEmailsOrIds, deleter, deleterHighestTopRole, hardDelete);
        if (!isLenient) {
            if (!validateInputsForDeleteUsersResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.badRequest().body(validateInputsForDeleteUsersResult.getMapOfErrors());
            } else if (validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
                return ResponseEntity.ok(Map.of("message", "No users deleted"));
            }
        }
        if (!validateInputsForDeleteUsersResult.getUsersToDelete().isEmpty()) {
            authServiceClient.revokeTokens(validateInputsForDeleteUsersResult.getUsersToDelete());
            if (hardDelete) {
                dbServiceClient.deleteUsers(validateInputsForDeleteUsersResult.getUsersToDelete());
            } else {
                dbServiceClient.updateUsers(validateInputsForDeleteUsersResult.getUsersToDelete());
            }
            if (isLenient && !validateInputsForDeleteUsersResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "message", "Some users deleted successfully",
                        "reasons_due_to_which_some_users_has_not_been_deleted", validateInputsForDeleteUsersResult.getMapOfErrors()
                ));
            }
            return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
        } else {
            if (!validateInputsForDeleteUsersResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "message", "No users deleted",
                        "reasons_due_to_which_users_has_not_been_deleted", validateInputsForDeleteUsersResult.getMapOfErrors()
                ));
            }
            return ResponseEntity.ok(Map.of("message", "No users deleted"));
        }
    }

    private boolean validateHardDeletion(String check,
                                         String name) {
        if (!isToggleExists(check)) {
            throw new SimpleBadRequestException("Unsupported " + name + " deletion type: " + check + ". Supported values: " + TOGGLE_TYPES);
        }
        return check.equalsIgnoreCase("enable");
    }

    private void checkUserCanHardDeleteUsers(String userHighestTopRole) {
        if (userHighestTopRole == null && !unleash.isEnabled(ALLOW_HARD_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name())) {
            throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
        }
    }

    private ValidateInputsForDeleteUsersResultDto validateInputsForDeleteUsers(Set<String> usernamesOrEmailsOrIds,
                                                                               UserModel deleter,
                                                                               String deleterHighestTopRole,
                                                                               boolean hardDelete) throws Exception {
        Variant variant = unleash.getVariant(ALLOW_DELETE_USERS.name());
        if (entryCheck(variant, deleterHighestTopRole)) {
            checkUserCanDeleteUsers(deleterHighestTopRole);
            validateInputsSizeForUsersDeletion(variant, usernamesOrEmailsOrIds);
            String decryptedDeleterUsername = aesStaticEncryptorDecryptor.decrypt(deleter.getUsername());
            String decryptedDeleterEmail = aesStaticEncryptorDecryptor.decrypt(deleter.getEmail());
            ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsersResult = validateInputsForDeleteOrReadUsers(usernamesOrEmailsOrIds, decryptedDeleterUsername, decryptedDeleterEmail, deleter.getId());
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!validateInputsForDeleteOrReadUsersResult.getInvalidInputs().isEmpty()) {
                mapOfErrors.put("invalid_inputs", validateInputsForDeleteOrReadUsersResult.getInvalidInputs());
            }
            if (!validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs().isEmpty()) {
                mapOfErrors.put("you_cannot_delete_your_own_account_using_this_endpoint", validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs());
            }
            return getUsersDeletionResult(validateInputsForDeleteOrReadUsersResult, decryptedDeleterUsername, deleterHighestTopRole, hardDelete, mapOfErrors);
        }
        throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
    }

    private void checkUserCanDeleteUsers(String deleterHighestTopPermission) {
        if (deleterHighestTopPermission == null && !unleash.isEnabled(ALLOW_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name())) {
            throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForUsersDeletion(Variant variant,
                                                    Set<String> usernamesOrEmailsOrIds) {
        if (usernamesOrEmailsOrIds.isEmpty()) {
            throw new SimpleBadRequestException("No users to delete");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToDeleteAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToDeleteAtATime < 1) {
                maxUsersToDeleteAtATime = DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME;
            }
            if (usernamesOrEmailsOrIds.size() > maxUsersToDeleteAtATime) {
                throw new SimpleBadRequestException("Cannot delete more than " + maxUsersToDeleteAtATime + " users at a time");
            }
        } else if (usernamesOrEmailsOrIds.size() > DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot delete more than " + DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME + " users at a time");
        }
    }

    private ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsers(Set<String> usernamesOrEmailsOrIds,
                                                                                           String userUsername,
                                                                                           String userEmail,
                                                                                           UUID id) {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> emails = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        Set<UUID> ids = new HashSet<>();
        Set<String> ownUserInInputs = new HashSet<>();
        usernamesOrEmailsOrIds.remove(null);
        for (String identifier : usernamesOrEmailsOrIds) {
            if (UUID_PATTERN.matcher(identifier).matches()) {
                ids.add(UUID.fromString(identifier));
            } else if (EMAIL_PATTERN.matcher(identifier).matches()) {
                emails.add(identifier);
            } else if (USERNAME_PATTERN.matcher(identifier).matches()) {
                usernames.add(identifier);
            } else {
                invalidInputs.add(identifier);
            }
        }
        if (usernames.contains(userUsername)) {
            ownUserInInputs.add(userUsername);
            usernames.remove(userUsername);
        }
        if (emails.contains(userEmail)) {
            ownUserInInputs.add(userEmail);
            emails.remove(userEmail);
        }
        if (ids.contains(id)) {
            ownUserInInputs.add(id.toString());
            ids.remove(id);
        }
        return new ValidateInputsForDeleteOrReadUsersResultDto(invalidInputs, usernames, emails, ids, ownUserInInputs);
    }

    private ValidateInputsForDeleteUsersResultDto getUsersDeletionResult(ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsersResult,
                                                                         String deleterUsername,
                                                                         String deleterHighestTopRole,
                                                                         boolean hardDelete,
                                                                         Map<String, Object> mapOfErrors) throws Exception {
        Set<String> tempSet = new HashSet<>();
        Map<String, String> tempMap = new HashMap<>();
        String tempStr;
        for (String username : validateInputsForDeleteOrReadUsersResult.getUsernames()) {
            tempStr = aesStaticEncryptorDecryptor.encrypt(username);
            tempSet.add(tempStr);
            tempMap.put(tempStr, username);
        }
        Set<UserModel> usersToDelete = new HashSet<>();
        Set<String> cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles = new HashSet<>();
        Set<String> cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers = new HashSet<>();
        boolean tempBoolean;
        for (UserModel userModel : dbServiceClient.getUsersByUsernameIn(tempSet)) {
            tempStr = tempMap.get(userModel.getUsername());
            validateInputsForDeleteOrReadUsersResult.getUsernames().remove(tempStr);
            tempBoolean = userDeletionResult(
                    userModel,
                    deleterUsername,
                    deleterHighestTopRole,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles,
                    usersToDelete,
                    hardDelete,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers,
                    tempStr
            );
            if (tempBoolean) {
                validateInputsForDeleteOrReadUsersResult.getUsernames().add(tempStr);
            }
        }
        tempSet.clear();
        tempMap.clear();
        for (String email : validateInputsForDeleteOrReadUsersResult.getEmails()) {
            tempStr = aesStaticEncryptorDecryptor.encrypt(email);
            tempSet.add(tempStr);
            tempMap.put(tempStr, email);
        }
        for (UserModel userModel : dbServiceClient.getUsersByEmailIn(tempSet)) {
            tempStr = tempMap.get(userModel.getEmail());
            validateInputsForDeleteOrReadUsersResult.getEmails().remove(tempStr);
            tempBoolean = userDeletionResult(
                    userModel,
                    deleterUsername,
                    deleterHighestTopRole,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles,
                    usersToDelete,
                    hardDelete,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers,
                    tempStr
            );
            if (tempBoolean) {
                validateInputsForDeleteOrReadUsersResult.getEmails().add(tempStr);
            }
        }
        for (UserModel userModel : dbServiceClient.getUsersByIdIn(validateInputsForDeleteOrReadUsersResult.getIds())) {
            validateInputsForDeleteOrReadUsersResult.getIds().remove(userModel.getId());
            tempBoolean = userDeletionResult(
                    userModel,
                    deleterUsername,
                    deleterHighestTopRole,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles,
                    usersToDelete,
                    hardDelete,
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers,
                    userModel.getId().toString()
            );
            if (tempBoolean) {
                validateInputsForDeleteOrReadUsersResult.getIds().add(userModel.getId());
            }
        }
        if (!validateInputsForDeleteOrReadUsersResult.getUsernames().isEmpty()) {
            mapOfErrors.put("users_not_found_with_usernames", validateInputsForDeleteOrReadUsersResult.getUsernames());
        }
        if (!validateInputsForDeleteOrReadUsersResult.getEmails().isEmpty()) {
            mapOfErrors.put("users_not_found_with_emails", validateInputsForDeleteOrReadUsersResult.getEmails());
        }
        if (!validateInputsForDeleteOrReadUsersResult.getIds().isEmpty()) {
            mapOfErrors.put("users_not_found_with_ids", validateInputsForDeleteOrReadUsersResult.getIds());
        }
        if (!cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles.isEmpty()) {
            mapOfErrors.put("cannot_delete_users_having_roles_higher_or_equal_than_deleter_roles", cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterRoles);
        }
        if (!cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers.isEmpty()) {
            mapOfErrors.put("cannot_delete_users_having_roles_higher_or_equal_than_deleter_identifiers", cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers);
        }
        return new ValidateInputsForDeleteUsersResultDto(mapOfErrors, usersToDelete);
    }

    private boolean userDeletionResult(UserModel userModel,
                                       String deleterUsername,
                                       String deleterHighestTopRole,
                                       Set<String> restrictedRoles,
                                       Set<UserModel> usersToDelete,
                                       boolean hardDelete,
                                       Set<String> cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers,
                                       String identifier) throws Exception {
        boolean recollectIdentifier = false;
        if (hardDelete) {
            boolean collectUser = validateRoleRestriction(userModel, deleterHighestTopRole, restrictedRoles);
            if (!collectUser) {
                usersToDelete.add(userModel);
            } else {
                cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers.add(identifier);
            }
        } else {
            if (!userModel.isAccountDeleted()) {
                boolean collectUser = validateRoleRestriction(userModel, deleterHighestTopRole, restrictedRoles);
                if (!collectUser) {
                    userModel.recordAccountDeletionStatus(true, aesRandomEncryptorDecryptor.encrypt(deleterUsername));
                    usersToDelete.add(userModel);
                } else {
                    cannotDeleteUsersHavingRolesHigherOrEqualThanDeleterIdentifiers.add(identifier);
                }
            } else {
                recollectIdentifier = true;
            }
        }
        return recollectIdentifier;
    }

    private boolean validateRoleRestriction(UserModel user,
                                            String userHighestTopRole,
                                            Set<String> restrictedRoles) {
        boolean isRestricted = false;
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            for (RoleModel role : user.getRoles()) {
                isRestricted = validateRoleRestriction(role.getRoleName(), restrictedRoles, userHighestTopRole) || isRestricted;
            }
        }
        return isRestricted;
    }

    public ResponseEntity<Map<String, Object>> readUsers(Set<String> usernamesOrEmailsOrIds,
                                                         String leniency,
                                                         HttpServletRequest request) throws Exception {
        Set<String> readerAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canReadUsers(readerAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String readerHighestTopRole = getUserHighestTopRole(readerAuthorities);
        Variant variant = unleash.getVariant(ALLOW_READ_USERS.name());
        if (entryCheck(variant, readerHighestTopRole)) {
            checkUserCanReadUsers(readerHighestTopRole);
            validateInputsSizeForUsersReading(variant, usernamesOrEmailsOrIds);
            ValidateInputsForDeleteOrReadUsersResultDto validateInputsForDeleteOrReadUsersResult = validateInputsForDeleteOrReadUsers(
                    usernamesOrEmailsOrIds,
                    aesStaticEncryptorDecryptor.decrypt(request.getHeader(X_USERNAME_HEADER)),
                    aesStaticEncryptorDecryptor.decrypt(request.getHeader(X_EMAIL_HEADER)),
                    UUID.fromString(request.getHeader(X_USER_ID_HEADER))
            );
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!validateInputsForDeleteOrReadUsersResult.getInvalidInputs().isEmpty()) {
                mapOfErrors.put("invalid_inputs", validateInputsForDeleteOrReadUsersResult.getInvalidInputs());
            }
            if (!validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs().isEmpty()) {
                for (String ownIdentifier : validateInputsForDeleteOrReadUsersResult.getOwnUserInInputs()) {
                    if (USERNAME_PATTERN.matcher(ownIdentifier).matches()) {
                        validateInputsForDeleteOrReadUsersResult.getUsernames().add(ownIdentifier);
                    } else if (EMAIL_PATTERN.matcher(ownIdentifier).matches()) {
                        validateInputsForDeleteOrReadUsersResult.getEmails().add(ownIdentifier);
                    } else if (UUID_PATTERN.matcher(ownIdentifier).matches()) {
                        validateInputsForDeleteOrReadUsersResult.getIds().add(UUID.fromString(ownIdentifier));
                    }
                }
            }
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (validateInputsForDeleteOrReadUsersResult.getUsernames().isEmpty() && validateInputsForDeleteOrReadUsersResult.getEmails().isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No users returned"));
                }
            } else if (validateInputsForDeleteOrReadUsersResult.getUsernames().isEmpty() && validateInputsForDeleteOrReadUsersResult.getEmails().isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users returned",
                            "reasons_due_to_users_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No users returned"));
            }
            Set<String> tempSet = new HashSet<>();
            Map<String, String> tempMap = new HashMap<>();
            String tempStr;
            for (String username : validateInputsForDeleteOrReadUsersResult.getUsernames()) {
                tempStr = aesStaticEncryptorDecryptor.encrypt(username);
                tempSet.add(tempStr);
                tempMap.put(tempStr, username);
            }
            List<UserSummaryToCompanyUsersDto> users = new ArrayList<>();
            for (UserModel userModel : dbServiceClient.getUsersByUsernameIn(tempSet)) {
                validateInputsForDeleteOrReadUsersResult.getUsernames().remove(tempMap.get(userModel.getUsername()));
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            tempSet.clear();
            tempMap.clear();
            for (String email : validateInputsForDeleteOrReadUsersResult.getEmails()) {
                tempStr = aesStaticEncryptorDecryptor.encrypt(email);
                tempSet.add(tempStr);
                tempMap.put(tempStr, email);
            }
            for (UserModel userModel : dbServiceClient.getUsersByEmailIn(tempSet)) {
                validateInputsForDeleteOrReadUsersResult.getEmails().remove(tempMap.get(userModel.getEmail()));
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            for (UserModel userModel : dbServiceClient.getUsersByIdIn(validateInputsForDeleteOrReadUsersResult.getIds())) {
                validateInputsForDeleteOrReadUsersResult.getIds().remove(userModel.getId());
                users.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            if (!validateInputsForDeleteOrReadUsersResult.getUsernames().isEmpty()) {
                mapOfErrors.put("users_not_found_with_usernames", validateInputsForDeleteOrReadUsersResult.getUsernames());
            }
            if (!validateInputsForDeleteOrReadUsersResult.getEmails().isEmpty()) {
                mapOfErrors.put("users_not_found_with_emails", validateInputsForDeleteOrReadUsersResult.getEmails());
            }
            if (!validateInputsForDeleteOrReadUsersResult.getIds().isEmpty()) {
                mapOfErrors.put("users_not_found_with_ids", validateInputsForDeleteOrReadUsersResult.getIds());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            if (users.isEmpty()) {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users returned",
                            "reasons_due_to_which_users_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No users returned"));
            } else {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "found_users", users,
                            "reasons_due_to_which_some_users_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("found_users", users));
            }
        }
        throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
    }

    private void checkUserCanReadUsers(String readerHighestTopRole) {
        if (readerHighestTopRole == null && !unleash.isEnabled(ALLOW_READ_USERS_BY_USERS_HAVE_PERMISSION_TO_READ_USERS.name())) {
            throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForUsersReading(Variant variant,
                                                   Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) {
            throw new SimpleBadRequestException("No users to read");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToReadAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToReadAtATime < 1) {
                maxUsersToReadAtATime = DEFAULT_MAX_USERS_TO_READ_AT_A_TIME;
            }
            if (usernamesOrEmails.size() > maxUsersToReadAtATime) {
                throw new SimpleBadRequestException("Cannot read more than " + maxUsersToReadAtATime + " users at a time");
            }
        } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_READ_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot read more than " + DEFAULT_MAX_USERS_TO_READ_AT_A_TIME + " users at a time");
        }
    }

    public ResponseEntity<Map<String, Object>> updateUsers(Set<UserUpdationDto> dtos,
                                                           String leniency,
                                                           HttpServletRequest request) throws Exception {
        Set<String> updaterAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canUpdateUsers(updaterAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String updaterHighestTopRole = getUserHighestTopRole(updaterAuthorities);
        Variant variant = unleash.getVariant(ALLOW_UPDATE_USERS.name());
        if (entryCheck(variant, updaterHighestTopRole)) {
            checkUserCanUpdateUsers(updaterHighestTopRole);
            validateDtosSizeForUsersUpdation(variant, dtos);
            ValidateInputsForUsersUpdationResultDto validateInputsForUsersUpdationResult = validateInputsForUsersUpdation(dtos, updaterHighestTopRole);
            Map<String, Object> mapOfErrors = errorsStuffingIfAny(validateInputsForUsersUpdationResult);
            moreErrorsStuffingIfAny(validateInputsForUsersUpdationResult, mapOfErrors, request.getHeader(X_USERNAME_HEADER));
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (dtos.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No users updated"));
                }
            } else if (dtos.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users updated",
                            "reasons_due_to_which_users_has_not_been_updated", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No users updated"));
                }
            }
            AlreadyTakenUsernamesAndEmailsResultDto alreadyTakenUsernamesAndEmailsResult = getConflictingUsernamesAndEmails(validateInputsForUsersUpdationResult);
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().isEmpty()) {
                mapOfErrors.put("usernames_already_taken", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames());
            }
            if (!alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().isEmpty()) {
                mapOfErrors.put("emails_already_taken", alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            UsersUpdationWithNewDetailsResultDto usersUpdationWithNewDetailsResult = updateUsersWithNewDetails(
                    dtos,
                    validateInputsForUsersUpdationResult,
                    alreadyTakenUsernamesAndEmailsResult,
                    request.getHeader(X_USERNAME_HEADER),
                    updaterHighestTopRole,
                    mapOfErrors
            );
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (usersUpdationWithNewDetailsResult.getUpdatedUsers().isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No users updated"));
                }
            } else if (usersUpdationWithNewDetailsResult.getUpdatedUsers().isEmpty()) {
                mapOfErrors.remove("missing_roles");
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No users updated",
                            "reasons_due_to_which_users_has_not_been_updated", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No users updated"));
                }
            }
            if (!usersUpdationWithNewDetailsResult.getIdsOfUsersWeHaveToRemoveTokens().isEmpty()) {
                authServiceClient.revokeTokensByUsersIds(usersUpdationWithNewDetailsResult.getIdsOfUsersWeHaveToRemoveTokens());
            }
            List<UserSummaryToCompanyUsersDto> updatedUsers = new ArrayList<>();
            for (UserModel userModel : dbServiceClient.updateUsers(usersUpdationWithNewDetailsResult.getUpdatedUsers())) {
                updatedUsers.add(mapperUtility.toUserSummaryToCompanyUsersDto(userModel));
            }
            mapOfErrors.remove("missing_roles");
            if (isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "updated_users", updatedUsers,
                        "reasons_due_to_which_some_users_has_not_been_updated", mapOfErrors
                ));
            }
            return ResponseEntity.ok(Map.of("updated_users", updatedUsers));
        }
        throw new ServiceUnavailableException("Updating users is currently disabled. Please try again later");
    }

    private void checkUserCanUpdateUsers(String updaterHighestTopRole) {
        if (updaterHighestTopRole == null && !unleash.isEnabled(ALLOW_UPDATE_USERS_BY_USERS_HAVE_PERMISSION_TO_UPDATE_USERS.name())) {
            throw new ServiceUnavailableException("Updating users is currently disabled. Please try again later");
        }
    }

    private void validateDtosSizeForUsersUpdation(Variant variant,
                                                  Set<UserUpdationDto> dtos) {
        if (dtos.isEmpty()) {
            throw new SimpleBadRequestException("No users to update");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxUsersToUpdateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToUpdateAtATime < 1) {
                maxUsersToUpdateAtATime = DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME;
            }
            if (dtos.size() > maxUsersToUpdateAtATime) {
                throw new SimpleBadRequestException("Cannot update more than " + maxUsersToUpdateAtATime + " users at a time");
            }
        } else if (dtos.size() > DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot update more than " + DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME + " users at a time");
        }
    }

    private ValidateInputsForUsersUpdationResultDto validateInputsForUsersUpdation(Set<UserUpdationDto> dtos,
                                                                                   String updaterHighestTopRole) throws Exception {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> usernames = new HashSet<>();
        Set<String> encryptedUsernames = new HashSet<>();
        Map<String, String> encryptedUsernameToUsernameMap = new HashMap<>();
        Map<String, String> usernameToEncryptedUsernameMap = new HashMap<>();
        Set<String> emails = new HashSet<>();
        Set<String> encryptedEmails = new HashSet<>();
        Map<String, String> encryptedEmailToEmailMap = new HashMap<>();
        Map<String, String> emailToEncryptedEmailMap = new HashMap<>();
        Set<String> duplicateUsernamesInDtos = new HashSet<>();
        Set<String> duplicateEmailsInDtos = new HashSet<>();
        Set<String> roles = new HashSet<>();
        Set<String> restrictedRoles = new HashSet<>();
        Set<String> oldUsernames = new HashSet<>();
        Set<String> encryptedOldUsernames = new HashSet<>();
        Map<String, String> encryptedOldUsernameToOldUsernameMap = new HashMap<>();
        Map<String, String> oldUsernameToEncryptedOldUsernameMap = new HashMap<>();
        Set<String> duplicateOldUsernames = new HashSet<>();
        Set<String> invalidOldUsernames = new HashSet<>();
        Map<String, String> encryptedUsernameToEncryptedOldUsernameMap = new HashMap<>();
        Map<String, String> encryptedEmailToEncryptedOldUsernameMap = new HashMap<>();
        dtos.remove(null);
        UserUpdationDto tempDto;
        boolean removeFromDtos;
        boolean removeFromDtosSanitizeRoles;
        String tempStr;
        String encryptedOldUsername;
        Iterator<UserUpdationDto> iterator = dtos.iterator();
        while (iterator.hasNext()) {
            removeFromDtos = false;
            removeFromDtosSanitizeRoles = false;
            tempDto = iterator.next();
            encryptedOldUsername = null;
            try {
                validateUsername(tempDto.getOldUsername());
                if (oldUsernames.add(tempDto.getOldUsername())) {
                    encryptedOldUsername = aesStaticEncryptorDecryptor.encrypt(tempDto.getOldUsername());
                    encryptedOldUsernames.add(encryptedOldUsername);
                    encryptedOldUsernameToOldUsernameMap.put(
                            encryptedOldUsername,
                            tempDto.getOldUsername()
                    );
                    oldUsernameToEncryptedOldUsernameMap.put(
                            tempDto.getOldUsername(),
                            encryptedOldUsername
                    );
                } else {
                    duplicateOldUsernames.add(tempDto.getOldUsername());
                    removeFromDtos = true;
                }
            } catch (SimpleBadRequestException ex) {
                invalidOldUsernames.add(tempDto.getOldUsername());
                removeFromDtos = true;
            }
            if (tempDto.getUsername() != null) {
                try {
                    validateUsername(tempDto.getUsername());
                    if (usernames.add(tempDto.getUsername())) {
                        tempStr = aesStaticEncryptorDecryptor.encrypt(tempDto.getUsername());
                        encryptedUsernames.add(tempStr);
                        encryptedUsernameToUsernameMap.put(
                                tempStr,
                                tempDto.getUsername()
                        );
                        usernameToEncryptedUsernameMap.put(
                                tempDto.getUsername(),
                                tempStr
                        );
                        if (encryptedOldUsername != null) {
                            encryptedUsernameToEncryptedOldUsernameMap.put(
                                    tempStr,
                                    encryptedOldUsername
                            );
                        }
                    } else {
                        duplicateUsernamesInDtos.add(tempDto.getUsername());
                        removeFromDtos = true;
                    }
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getEmail() != null) {
                try {
                    validateEmail(tempDto.getEmail());
                    if (emails.add(tempDto.getEmail())) {
                        tempStr = aesStaticEncryptorDecryptor.encrypt(tempDto.getEmail());
                        encryptedEmails.add(tempStr);
                        encryptedEmailToEmailMap.put(
                                tempStr,
                                tempDto.getEmail()
                        );
                        emailToEncryptedEmailMap.put(
                                tempDto.getEmail(),
                                tempStr
                        );
                        if (encryptedOldUsername != null) {
                            encryptedEmailToEncryptedOldUsernameMap.put(
                                    tempStr,
                                    encryptedOldUsername
                            );
                        }
                    } else {
                        duplicateEmailsInDtos.add(tempDto.getEmail());
                        removeFromDtos = true;
                    }
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getRoles() != null && !tempDto.getRoles().isEmpty()) {
                removeFromDtosSanitizeRoles = sanitizeRoles(
                        tempDto.getRoles(),
                        restrictedRoles,
                        updaterHighestTopRole,
                        roles
                );
            }
            if (tempDto.getAllowedConcurrentLogins() != 0 && tempDto.getAllowedConcurrentLogins() < 1) {
                invalidInputs.add("Allowed concurrent logins must be at least 1");
                removeFromDtos = true;
            }
            if (tempDto.getFirstName() != null) {
                try {
                    validateFirstName(tempDto.getFirstName());
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getMiddleName() != null) {
                try {
                    validateMiddleName(tempDto.getMiddleName());
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getLastName() != null) {
                try {
                    validateLastName(tempDto.getLastName());
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (tempDto.getPassword() != null) {
                try {
                    validatePassword(tempDto.getPassword());
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                    removeFromDtos = true;
                }
            }
            if (removeFromDtos || removeFromDtosSanitizeRoles) {
                iterator.remove();
            }
        }
        return new ValidateInputsForUsersUpdationResultDto(
                invalidInputs,
                encryptedUsernames,
                encryptedUsernameToUsernameMap,
                usernameToEncryptedUsernameMap,
                encryptedEmails,
                encryptedEmailToEmailMap,
                emailToEncryptedEmailMap,
                duplicateUsernamesInDtos,
                duplicateEmailsInDtos,
                roles,
                restrictedRoles,
                encryptedOldUsernames,
                encryptedOldUsernameToOldUsernameMap,
                oldUsernameToEncryptedOldUsernameMap,
                duplicateOldUsernames,
                invalidOldUsernames,
                encryptedUsernameToEncryptedOldUsernameMap,
                encryptedEmailToEncryptedOldUsernameMap
        );
    }

    private void moreErrorsStuffingIfAny(ValidateInputsForUsersUpdationResultDto validateInputsForUsersUpdationResult,
                                         Map<String, Object> mapOfErrors,
                                         String encryptedUpdaterUsername) {
        if (!validateInputsForUsersUpdationResult.getDuplicateOldUsernames().isEmpty()) {
            mapOfErrors.put("duplicate_old_usernames_in_request", validateInputsForUsersUpdationResult.getDuplicateOldUsernames());
        }
        if (!validateInputsForUsersUpdationResult.getInvalidOldUsernames().isEmpty()) {
            mapOfErrors.put("invalid_old_usernames", validateInputsForUsersUpdationResult.getInvalidOldUsernames());
        }
        if (validateInputsForUsersUpdationResult.getEncryptedOldUsernames().contains(encryptedUpdaterUsername)) {
            mapOfErrors.put("cannot_update_own_account_using_this_endpoint", validateInputsForUsersUpdationResult.getEncryptedOldUsernameToOldUsernameMap().get(encryptedUpdaterUsername));
        }
    }

    private AlreadyTakenUsernamesAndEmailsResultDto getConflictingUsernamesAndEmails(ValidateInputsForUsersUpdationResultDto validateInputsForUsersUpdationResult) {
        Set<String> alreadyTakenUsernames = new HashSet<>();
        Set<String> alreadyTakenEmails = new HashSet<>();
        String requesterer;
        for (UserModel userModel : dbServiceClient.getUsersByUsernameIn(validateInputsForUsersUpdationResult.getEncryptedUsernames())) {
            requesterer = validateInputsForUsersUpdationResult.getEncryptedUsernameToEncryptedOldUsernameMap().get(userModel.getUsername());
            if (requesterer != null && !userModel.getUsername().equals(requesterer)) {
                alreadyTakenUsernames.add(validateInputsForUsersUpdationResult.getEncryptedUsernameToUsernameMap().get(userModel.getUsername()));
            }
        }
        for (UserModel userModel : dbServiceClient.getUsersByEmailIn(validateInputsForUsersUpdationResult.getEncryptedEmails())) {
            requesterer = validateInputsForUsersUpdationResult.getEncryptedEmailToEncryptedOldUsernameMap().get(userModel.getEmail());
            if (requesterer != null && !userModel.getUsername().equals(requesterer)) {
                alreadyTakenEmails.add(validateInputsForUsersUpdationResult.getEncryptedEmailToEmailMap().get(userModel.getEmail()));
            }
        }
        return new AlreadyTakenUsernamesAndEmailsResultDto(alreadyTakenUsernames, alreadyTakenEmails);
    }

    private UsersUpdationWithNewDetailsResultDto updateUsersWithNewDetails(Set<UserUpdationDto> dtos,
                                                                           ValidateInputsForUsersUpdationResultDto validateInputsForUsersUpdationResult,
                                                                           AlreadyTakenUsernamesAndEmailsResultDto alreadyTakenUsernamesAndEmailsResult,
                                                                           String encryptedUpdaterUsername,
                                                                           String updaterHighestTopRole,
                                                                           Map<String, Object> mapOfErrors) throws Exception {
        Map<String, UserModel> encryptedOldUsernameToUserMap = new HashMap<>();
        for (UserModel user : dbServiceClient.getUsersByUsernameIn(validateInputsForUsersUpdationResult.getEncryptedOldUsernames())) {
            encryptedOldUsernameToUserMap.put(user.getUsername(), user);
        }
        Map<String, RoleModel> roleNameToRoleMap = resolveRoles(validateInputsForUsersUpdationResult.getRoles());
        if (!validateInputsForUsersUpdationResult.getRoles().isEmpty()) {
            mapOfErrors.put("missing_roles", validateInputsForUsersUpdationResult.getRoles());
        }
        Set<UserModel> updatedUsers = new HashSet<>();
        Set<UUID> idsOfUsersWeHaveToRemoveTokens = new HashSet<>();
        Set<String> cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterRoles = new HashSet<>();
        Set<String> cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterUsernames = new HashSet<>();
        Set<String> notFoundUsersWithOldUsernames = new HashSet<>();
        String tempStr;
        boolean isUpdated;
        boolean shouldRemoveTokens;
        boolean tempBoolean;
        String decryptedUpdaterUsername = aesStaticEncryptorDecryptor.decrypt(encryptedUpdaterUsername);
        for (UserUpdationDto dto : dtos) {
            tempStr = dto.getOldUsername();
            if (tempStr.equals(decryptedUpdaterUsername)) {
                continue;
            }
            UserModel userToUpdate = encryptedOldUsernameToUserMap.get(validateInputsForUsersUpdationResult.getOldUsernameToEncryptedOldUsernameMap().get(tempStr));
            if (userToUpdate == null) {
                notFoundUsersWithOldUsernames.add(tempStr);
                continue;
            }
            if (!userToUpdate.getRoles().isEmpty()) {
                tempBoolean = validateRoleRestriction(
                        userToUpdate,
                        updaterHighestTopRole,
                        cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterRoles
                );
                if (tempBoolean) {
                    cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterUsernames.add(tempStr);
                    continue;
                }
            }
            isUpdated = false;
            shouldRemoveTokens = false;
            if (dto.getUsername() != null) {
                if (alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenUsernames().contains(dto.getUsername())) {
                    continue;
                }
                tempStr = validateInputsForUsersUpdationResult.getUsernameToEncryptedUsernameMap().get(dto.getUsername());
                if (!tempStr.equals(userToUpdate.getUsername())) {
                    userToUpdate.setUsername(tempStr);
                    isUpdated = true;
                    shouldRemoveTokens = true;
                }
            }
            if (dto.getEmail() != null) {
                if (alreadyTakenUsernamesAndEmailsResult.getAlreadyTakenEmails().contains(dto.getEmail())) {
                    continue;
                }
                tempStr = validateInputsForUsersUpdationResult.getEmailToEncryptedEmailMap().get(dto.getEmail());
                if (!tempStr.equals(userToUpdate.getEmail())) {
                    userToUpdate.setEmail(tempStr);
                    userToUpdate.setRealEmail(tempStr);
                    isUpdated = true;
                    shouldRemoveTokens = true;
                }
            }
            if (dto.getPassword() != null) {
                userToUpdate.recordPasswordChange(passwordEncoder.encode(dto.getPassword()));
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.getFirstName() != null && !dto.getFirstName().equals(userToUpdate.getFirstName())) {
                userToUpdate.setFirstName(dto.getFirstName());
                isUpdated = true;
            }
            if (dto.getMiddleName() != null && !dto.getMiddleName().equals(userToUpdate.getMiddleName())) {
                userToUpdate.setMiddleName(dto.getMiddleName());
                isUpdated = true;
            }
            if (dto.getLastName() != null && !dto.getLastName().equals(userToUpdate.getLastName())) {
                userToUpdate.setLastName(dto.getLastName());
                isUpdated = true;
            }
            if (dto.getRoles() != null) {
                if (dto.getRoles().isEmpty()) {
                    if (!userToUpdate.getRoles().isEmpty()) {
                        userToUpdate.getRoles().clear();
                        isUpdated = true;
                        shouldRemoveTokens = true;
                    }
                } else {
                    Set<RoleModel> rolesToAssign = new HashSet<>();
                    for (String roleName : dto.getRoles()) {
                        RoleModel role = roleNameToRoleMap.get(roleName);
                        if (role != null) {
                            rolesToAssign.add(role);
                        }
                    }
                    if (!userToUpdate.getRoles().equals(rolesToAssign)) {
                        userToUpdate.setRoles(rolesToAssign);
                        isUpdated = true;
                        shouldRemoveTokens = true;
                    }
                }
            }
            if (dto.getAllowedConcurrentLogins() != 0 && dto.getAllowedConcurrentLogins() != userToUpdate.getAllowedConcurrentLogins()) {
                userToUpdate.setAllowedConcurrentLogins(dto.getAllowedConcurrentLogins());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isEmailVerified() != userToUpdate.isEmailVerified()) {
                userToUpdate.setEmailVerified(dto.isEmailVerified());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountEnabled() != userToUpdate.isAccountEnabled()) {
                userToUpdate.setAccountEnabled(dto.isAccountEnabled());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountLocked() != userToUpdate.isAccountLocked()) {
                userToUpdate.recordLockedStatus(dto.isAccountLocked());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountDeleted() != userToUpdate.isAccountDeleted()) {
                userToUpdate.recordAccountDeletionStatus(
                        dto.isAccountDeleted(),
                        aesRandomEncryptorDecryptor.encrypt(decryptedUpdaterUsername)
                );
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (isUpdated) {
                userToUpdate.recordUpdation(aesRandomEncryptorDecryptor.encrypt(decryptedUpdaterUsername));
                updatedUsers.add(userToUpdate);
                if (shouldRemoveTokens) {
                    idsOfUsersWeHaveToRemoveTokens.add(userToUpdate.getId());
                }
            }
        }
        if (!notFoundUsersWithOldUsernames.isEmpty()) {
            mapOfErrors.put("users_not_found_with_old_usernames", notFoundUsersWithOldUsernames);
        }
        if (!cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterRoles.isEmpty()) {
            mapOfErrors.put("cannot_update_users_having_roles_higher_or_equal_than_updater_roles", cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterRoles);
        }
        if (!cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterUsernames.isEmpty()) {
            mapOfErrors.put("cannot_update_users_having_roles_higher_or_equal_than_updater_usernames", cannotUpdateUsersHavingRolesHigherOrEqualThanUpdaterUsernames);
        }
        return new UsersUpdationWithNewDetailsResultDto(updatedUsers, idsOfUsersWeHaveToRemoveTokens);
    }

    public ResponseEntity<Map<String, Object>> createRoles(Set<RoleCreationUpdationDto> dtos,
                                                           String leniency,
                                                           HttpServletRequest request) throws Exception {
        Set<String> creatorAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canCreateRoles(creatorAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String creatorHighestTopRole = getUserHighestTopRole(creatorAuthorities);
        Variant variant = unleash.getVariant(ALLOW_CREATE_ROLES.name());
        if (entryCheck(variant, creatorHighestTopRole)) {
            checkUserCanCreateRoles(creatorHighestTopRole);
            validateDtosSizeForRolesCreation(variant, dtos);
            ValidateInputsForRolesCreationOrUpdationResultDto validateInputsForRolesCreationResult = validateInputsForRolesCreationOrUpdation(dtos);
            Map<String, Object> mapOfErrors = errorsStuffingIfAny(validateInputsForRolesCreationResult);
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (dtos.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No roles created"));
                }
            } else if (dtos.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles created",
                            "reasons_due_to_which_roles_has_not_been_created", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No roles created"));
                }
            }
            Set<String> alreadyTakenRoleNames = getAlreadyTakenRoleNames(validateInputsForRolesCreationResult.getRoleNames());
            if (!alreadyTakenRoleNames.isEmpty()) {
                mapOfErrors.put("role_names_already_taken", alreadyTakenRoleNames);
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            Map<String, PermissionModel> resolvedPermissionsMap = resolvePermissions(validateInputsForRolesCreationResult.getPermissions());
            if (!validateInputsForRolesCreationResult.getPermissions().isEmpty()) {
                mapOfErrors.put("missing_permissions", validateInputsForRolesCreationResult.getPermissions());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            Set<RoleModel> newRoles = new HashSet<>();
            String decryptedCreatorUsername = aesStaticEncryptorDecryptor.decrypt(request.getHeader(X_USERNAME_HEADER));
            for (RoleCreationUpdationDto dto : dtos) {
                if (alreadyTakenRoleNames.contains(dto.getRoleName())) {
                    continue;
                }
                if (dto.getPermissions() == null || dto.getPermissions().isEmpty()) {
                    newRoles.add(toRoleModel(dto, new HashSet<>(), decryptedCreatorUsername));
                } else {
                    Set<PermissionModel> permissionsToAssign = new HashSet<>();
                    for (String permissionName : dto.getPermissions()) {
                        PermissionModel permission = resolvedPermissionsMap.get(permissionName);
                        if (permission != null) {
                            permissionsToAssign.add(permission);
                        }
                    }
                    newRoles.add(toRoleModel(dto, permissionsToAssign, decryptedCreatorUsername));
                }
            }
            mapOfErrors.remove("missing_permissions");
            if (newRoles.isEmpty()) {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles created",
                            "reasons_due_to_which_roles_has_not_been_created", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No roles created"));
            }
            List<RoleSummaryDto> roles = new ArrayList<>();
            for (RoleModel role : dbServiceClient.createRoles(newRoles)) {
                roles.add(mapperUtility.toRoleSummaryDto(role));
            }
            if (isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "created_roles", roles,
                        "reasons_due_to_which_some_roles_has_not_been_created", mapOfErrors
                ));
            }
            return ResponseEntity.ok(Map.of("created_roles", roles));
        }
        throw new ServiceUnavailableException("Creating roles is currently disabled. Please try again later");
    }

    private void checkUserCanCreateRoles(String creatorHighestTopRole) {
        if (creatorHighestTopRole == null && !unleash.isEnabled(ALLOW_CREATE_ROLES_BY_USERS_HAVE_PERMISSION_TO_CREATE_ROLES.name())) {
            throw new ServiceUnavailableException("Creating roles is currently disabled. Please try again later");
        }
    }

    private void validateDtosSizeForRolesCreation(Variant variant,
                                                  Set<RoleCreationUpdationDto> dtos) {
        if (dtos.isEmpty()) {
            throw new SimpleBadRequestException("No roles to create");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxRolesToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxRolesToCreateAtATime < 1) {
                maxRolesToCreateAtATime = DEFAULT_MAX_ROLES_TO_CREATE_AT_A_TIME;
            }
            if (dtos.size() > maxRolesToCreateAtATime) {
                throw new SimpleBadRequestException("Cannot create more than " + maxRolesToCreateAtATime + " roles at a time");
            }
        } else if (dtos.size() > DEFAULT_MAX_ROLES_TO_CREATE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot create more than " + DEFAULT_MAX_ROLES_TO_CREATE_AT_A_TIME + " roles at a time");
        }
    }

    private ValidateInputsForRolesCreationOrUpdationResultDto validateInputsForRolesCreationOrUpdation(Set<RoleCreationUpdationDto> dtos) {
        Set<String> invalidInputs = new HashSet<>();
        Set<String> roleNames = new HashSet<>();
        Set<String> duplicateRoleNamesInDtos = new HashSet<>();
        Set<String> permissions = new HashSet<>();
        dtos.remove(null);
        Iterator<RoleCreationUpdationDto> iterator = dtos.iterator();
        boolean removeFromDtos;
        RoleCreationUpdationDto tempDto;
        while (iterator.hasNext()) {
            removeFromDtos = false;
            tempDto = iterator.next();
            try {
                validateRoleNameOrPermissionName(tempDto.getRoleName(), "Role name");
                if (!roleNames.add(tempDto.getRoleName())) {
                    duplicateRoleNamesInDtos.add(tempDto.getRoleName());
                    removeFromDtos = true;
                }
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(ex.getMessage());
                removeFromDtos = true;
            }
            if (tempDto.getDescription() != null && tempDto.getDescription().length() > 255) {
                invalidInputs.add("Description must be at most 255 characters long");
                removeFromDtos = true;
            }
            if (tempDto.getPermissions() != null && !tempDto.getPermissions().isEmpty()) {
                sanitizePermissionNames(tempDto.getPermissions(), permissions);
            }
            if (removeFromDtos) {
                iterator.remove();
            }
        }
        return new ValidateInputsForRolesCreationOrUpdationResultDto(
                invalidInputs,
                roleNames,
                duplicateRoleNamesInDtos,
                permissions
        );
    }

    private void sanitizePermissionNames(Set<String> permissionNames,
                                         Set<String> permissionsCollector) {
        permissionNames.remove(null);
        Iterator<String> iterator = permissionNames.iterator();
        String temp;
        while (iterator.hasNext()) {
            temp = iterator.next();
            if (temp.isBlank()) {
                iterator.remove();
            } else {
                permissionsCollector.add(temp);
            }
        }
    }

    private Map<String, Object> errorsStuffingIfAny(ValidateInputsForRolesCreationOrUpdationResultDto validateInputsForRolesCreationOrUpdationResult) {
        Map<String, Object> mapOfErrors = new HashMap<>();
        if (!validateInputsForRolesCreationOrUpdationResult.getInvalidInputs().isEmpty()) {
            mapOfErrors.put("invalid_inputs", validateInputsForRolesCreationOrUpdationResult.getInvalidInputs());
        }
        if (!validateInputsForRolesCreationOrUpdationResult.getDuplicateRoleNamesInDtos().isEmpty()) {
            mapOfErrors.put("duplicate_role_names_in_request", validateInputsForRolesCreationOrUpdationResult.getDuplicateRoleNamesInDtos());
        }
        return mapOfErrors;
    }

    private Set<String> getAlreadyTakenRoleNames(Set<String> roleNames) {
        Set<String> alreadyTakenRoleNames = new HashSet<>();
        if (!roleNames.isEmpty()) {
            for (RoleModel role : dbServiceClient.getRolesByIdIn(roleNames)) {
                alreadyTakenRoleNames.add(role.getRoleName());
            }
        }
        return alreadyTakenRoleNames;
    }

    private Map<String, PermissionModel> resolvePermissions(Set<String> permissions) {
        if (permissions.isEmpty()) {
            return new HashMap<>();
        }
        Map<String, PermissionModel> resolvedRolesMap = new HashMap<>();
        for (PermissionModel permission : dbServiceClient.getPermissionsByIdIn(permissions)) {
            permissions.remove(permission.getPermissionName());
            resolvedRolesMap.put(
                    permission.getPermissionName(),
                    permission
            );
        }
        return resolvedRolesMap;
    }

    private RoleModel toRoleModel(RoleCreationUpdationDto dto,
                                  Set<PermissionModel> permissions,
                                  String creator) throws Exception {
        return RoleModel.builder()
                .roleName(dto.getRoleName())
                .description(dto.getDescription())
                .permissions(permissions)
                .createdBy(aesRandomEncryptorDecryptor.encrypt(creator))
                .build();
    }

    public ResponseEntity<Map<String, Object>> deleteRoles(Set<String> roleNames,
                                                           String force,
                                                           String leniency,
                                                           HttpServletRequest request) {
        Set<String> deleterAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canDeleteRoles(deleterAuthorities);
        boolean forceDelete = validateHardDeletion(force, "force");
        boolean isLenient = validateLeniency(leniency);
        String deleterHighestTopRole = getUserHighestTopRole(deleterAuthorities);
        if (forceDelete) {
            if (unleash.isEnabled(ALLOW_FORCE_DELETE_ROLES.name()) || TOP_ROLES.getFirst().equals(deleterHighestTopRole)) {
                checkUserCanForceDeleteRoles(deleterHighestTopRole);
            } else {
                throw new ServiceUnavailableException("Force deletion of roles is currently disabled. Please try again later");
            }
        }
        ValidateInputsForDeleteRolesResultDto validateInputsForDeleteRolesResult = validateInputsForDeleteRoles(roleNames, deleterHighestTopRole, forceDelete);
        if (!isLenient) {
            if (!validateInputsForDeleteRolesResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.badRequest().body(validateInputsForDeleteRolesResult.getMapOfErrors());
            } else if (validateInputsForDeleteRolesResult.getRolesToDelete().isEmpty()) {
                return ResponseEntity.ok(Map.of("message", "No roles deleted"));
            }
        }
        if (!validateInputsForDeleteRolesResult.getRolesToDelete().isEmpty()) {
            dbServiceClient.deleteRoles(validateInputsForDeleteRolesResult.getRolesToDelete());
            if (isLenient && !validateInputsForDeleteRolesResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "message", "Some roles deleted successfully",
                        "reasons_due_to_which_some_roles_has_not_been_deleted", validateInputsForDeleteRolesResult.getMapOfErrors()
                ));
            }
            return ResponseEntity.ok(Map.of("message", "Roles deleted successfully"));
        } else {
            if (!validateInputsForDeleteRolesResult.getMapOfErrors().isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "message", "No roles deleted",
                        "reasons_due_to_which_roles_has_not_been_deleted", validateInputsForDeleteRolesResult.getMapOfErrors()
                ));
            }
            return ResponseEntity.ok(Map.of("message", "No roles deleted"));
        }
    }

    private void checkUserCanForceDeleteRoles(String deleterHighestTopRole) {
        if (deleterHighestTopRole == null && !unleash.isEnabled(ALLOW_FORCE_DELETE_ROLES_BY_USERS_HAVE_PERMISSION_TO_DELETE_ROLES.name())) {
            throw new ServiceUnavailableException("Force deletion of roles is currently disabled. Please try again later");
        }
    }

    private ValidateInputsForDeleteRolesResultDto validateInputsForDeleteRoles(Set<String> roleNames,
                                                                               String deleterHighestTopRole,
                                                                               boolean forceDelete) {
        Variant variant = unleash.getVariant(ALLOW_DELETE_ROLES.name());
        if (entryCheck(variant, deleterHighestTopRole)) {
            checkUserCanDeleteRoles(deleterHighestTopRole);
            validateInputsSizeForRolesToDelete(variant, roleNames);
            Set<String> invalidInputs = validateInputsForDeleteOrReadRoles(roleNames);
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!invalidInputs.isEmpty()) {
                mapOfErrors.put("invalid_role_names", invalidInputs);
            }
            return getRolesDeletionResult(roleNames, forceDelete, mapOfErrors);
        }
        throw new ServiceUnavailableException("Deletion of roles is currently disabled. Please try again later");
    }

    private void checkUserCanDeleteRoles(String deleterHighestTopRole) {
        if (deleterHighestTopRole == null && !unleash.isEnabled(ALLOW_DELETE_ROLES_BY_USERS_HAVE_PERMISSION_TO_DELETE_ROLES.name())) {
            throw new ServiceUnavailableException("Deleting roles is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForRolesToDelete(Variant variant,
                                                    Set<String> roleNames) {
        if (roleNames.isEmpty()) {
            throw new SimpleBadRequestException("No roles to delete");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxRolesToDeleteAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxRolesToDeleteAtATime < 1) {
                maxRolesToDeleteAtATime = DEFAULT_MAX_ROLES_TO_DELETE_AT_A_TIME;
            }
            if (roleNames.size() > maxRolesToDeleteAtATime) {
                throw new SimpleBadRequestException("Cannot delete more than " + maxRolesToDeleteAtATime + " roles at a time");
            }
        } else if (roleNames.size() > DEFAULT_MAX_ROLES_TO_DELETE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot delete more than " + DEFAULT_MAX_ROLES_TO_DELETE_AT_A_TIME + " roles at a time");
        }
    }

    private Set<String> validateInputsForDeleteOrReadRoles(Set<String> roleNames) {
        Set<String> invalidInputs = new HashSet<>();
        roleNames.remove(null);
        Iterator<String> iterator = roleNames.iterator();
        String temp;
        while (iterator.hasNext()) {
            temp = iterator.next();
            try {
                validateRoleNameOrPermissionName(temp, "Role name");
            } catch (SimpleBadRequestException ex) {
                invalidInputs.add(temp);
                iterator.remove();
            }
        }
        return invalidInputs;
    }

    private ValidateInputsForDeleteRolesResultDto getRolesDeletionResult(Set<String> roleNames,
                                                                         boolean forceDelete,
                                                                         Map<String, Object> mapOfErrors) {
        Set<String> systemRoleNames = new HashSet<>();
        Set<RoleModel> rolesToDelete = new HashSet<>();
        Set<UUID> idsOfUsersWeHaveToRemoveTokens = new HashSet<>();
        Set<String> roleNamesThatIsAssignedToUsers = new HashSet<>();
        for (RoleModel role : dbServiceClient.getRolesByIdIn(roleNames)) {
            roleNames.remove(role.getRoleName());
            if (role.isSystemRole()) {
                systemRoleNames.add(role.getRoleName());
            } else {
                roleDeletionResult(
                        role,
                        forceDelete,
                        idsOfUsersWeHaveToRemoveTokens,
                        roleNamesThatIsAssignedToUsers,
                        rolesToDelete
                );
            }
        }
        if (!roleNames.isEmpty()) {
            mapOfErrors.put("roles_not_found", roleNames);
        }
        if (!systemRoleNames.isEmpty()) {
            mapOfErrors.put("system_roles_cannot_be_deleted", systemRoleNames);
        }
        if (forceDelete) {
            if (!roleNamesThatIsAssignedToUsers.isEmpty()) {
                dbServiceClient.deleteUserRolesByRoleNames(roleNamesThatIsAssignedToUsers);
                authServiceClient.revokeTokensByUsersIds(idsOfUsersWeHaveToRemoveTokens);
            }
        } else {
            if (!roleNamesThatIsAssignedToUsers.isEmpty()) {
                mapOfErrors.put("roles_assigned_to_users", roleNamesThatIsAssignedToUsers);
            }
        }
        return new ValidateInputsForDeleteRolesResultDto(mapOfErrors, rolesToDelete);
    }

    private void roleDeletionResult(RoleModel role,
                                    boolean forceDelete,
                                    Set<UUID> idsOfUsersWeHaveToRemoveTokens,
                                    Set<String> roleNamesThatIsAssignedToUsers,
                                    Set<RoleModel> rolesToDelete) {
        Collection<UUID> userIdsOfUsersHavingThisRole = dbServiceClient.getUserIdsByRoleNames(Set.of(role.getRoleName()));
        if (userIdsOfUsersHavingThisRole.isEmpty()) {
            rolesToDelete.add(role);
        } else {
            if (forceDelete) {
                idsOfUsersWeHaveToRemoveTokens.addAll(userIdsOfUsersHavingThisRole);
                roleNamesThatIsAssignedToUsers.add(role.getRoleName());
                rolesToDelete.add(role);
            } else {
                roleNamesThatIsAssignedToUsers.add(role.getRoleName());
            }
        }
    }

    public ResponseEntity<Map<String, Object>> readRoles(Set<String> roleNames,
                                                         String leniency,
                                                         HttpServletRequest request) throws Exception {
        Set<String> readerAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canReadRoles(readerAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String readerHighestTopRole = getUserHighestTopRole(readerAuthorities);
        Variant variant = unleash.getVariant(ALLOW_READ_ROLES.name());
        if (entryCheck(variant, readerHighestTopRole)) {
            checkUserCanReadRoles(readerHighestTopRole);
            validateInputsSizeForRolesToRead(variant, roleNames);
            Set<String> invalidInputs = validateInputsForDeleteOrReadRoles(roleNames);
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!invalidInputs.isEmpty()) {
                mapOfErrors.put("invalid_role_names", invalidInputs);
            }
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (roleNames.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No roles returned"));
                }
            } else if (roleNames.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles returned",
                            "reasons_due_to_which_roles_has_not_been_returned", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No roles returned"));
                }
            }
            List<RoleSummaryDto> roles = new ArrayList<>();
            for (RoleModel role : dbServiceClient.getRolesByIdIn(roleNames)) {
                roles.add(mapperUtility.toRoleSummaryDto(role));
                roleNames.remove(role.getRoleName());
            }
            if (!roleNames.isEmpty()) {
                mapOfErrors.put("roles_not_found", roleNames);
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            if (roles.isEmpty()) {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles returned",
                            "reasons_due_to_which_roles_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No roles returned"));
            } else {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "found_roles", roles,
                            "reasons_due_to_which_some_roles_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("found_roles", roles));
            }
        }
        throw new ServiceUnavailableException("Reading roles is currently disabled. Please try again later");
    }

    private void checkUserCanReadRoles(String readerHighestTopRole) {
        if (readerHighestTopRole == null && !unleash.isEnabled(ALLOW_READ_ROLES_BY_USERS_HAVE_PERMISSION_TO_READ_ROLES.name())) {
            throw new ServiceUnavailableException("Reading roles is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForRolesToRead(Variant variant,
                                                  Set<String> roleNames) {
        if (roleNames.isEmpty()) {
            throw new SimpleBadRequestException("No roles to read");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxRolesToReadAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxRolesToReadAtATime < 1) {
                maxRolesToReadAtATime = DEFAULT_MAX_ROLES_TO_READ_AT_A_TIME;
            }
            if (roleNames.size() > maxRolesToReadAtATime) {
                throw new SimpleBadRequestException("Cannot read more than " + maxRolesToReadAtATime + " roles at a time");
            }
        } else if (roleNames.size() > DEFAULT_MAX_ROLES_TO_READ_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot read more than " + DEFAULT_MAX_ROLES_TO_READ_AT_A_TIME + " roles at a time");
        }
    }

    public ResponseEntity<Map<String, Object>> updateRoles(Set<RoleCreationUpdationDto> dtos,
                                                           String leniency,
                                                           HttpServletRequest request) throws Exception {
        Set<String> updaterAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canUpdateRoles(updaterAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String updaterHighestTopRole = getUserHighestTopRole(updaterAuthorities);
        Variant variant = unleash.getVariant(ALLOW_UPDATE_ROLES.name());
        if (entryCheck(variant, updaterHighestTopRole)) {
            checkUserCanUpdateRoles(updaterHighestTopRole);
            validateDtosSizeForRolesUpdation(variant, dtos);
            ValidateInputsForRolesCreationOrUpdationResultDto validateInputsForRolesUpdationResult = validateInputsForRolesCreationOrUpdation(dtos);
            Map<String, Object> mapOfErrors = errorsStuffingIfAny(validateInputsForRolesUpdationResult);
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (dtos.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            } else if (dtos.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles updated",
                            "reasons_due_to_which_roles_has_not_been_updated", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            }
            Map<String, RoleModel> roleNameToRoleMap = new HashMap<>();
            Set<String> systemRoleNames = new HashSet<>();
            for (RoleModel role : dbServiceClient.getRolesByIdIn(validateInputsForRolesUpdationResult.getRoleNames())) {
                validateInputsForRolesUpdationResult.getRoleNames().remove(role.getRoleName());
                if (!role.isSystemRole()) {
                    roleNameToRoleMap.put(role.getRoleName(), role);
                } else {
                    systemRoleNames.add(role.getRoleName());
                }
            }
            if (!validateInputsForRolesUpdationResult.getRoleNames().isEmpty()) {
                mapOfErrors.put("roles_not_found", validateInputsForRolesUpdationResult.getRoleNames());
            }
            if (!systemRoleNames.isEmpty()) {
                mapOfErrors.put("system_roles_cannot_be_updated", systemRoleNames);
            }
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (roleNameToRoleMap.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            } else if (roleNameToRoleMap.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles updated",
                            "reasons_due_to_which_roles_has_not_been_updated", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            }
            Map<String, PermissionModel> resolvedPermissionsMap = resolvePermissions(validateInputsForRolesUpdationResult.getPermissions());
            if (!validateInputsForRolesUpdationResult.getPermissions().isEmpty()) {
                mapOfErrors.put("missing_permissions", validateInputsForRolesUpdationResult.getPermissions());
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            RolesUpdationWithNewDetailsResultDto rolesUpdationWithNewDetailsResult = updateRolesWithNewDetails(
                    dtos,
                    roleNameToRoleMap,
                    resolvedPermissionsMap,
                    request.getHeader(X_USERNAME_HEADER)
            );
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (rolesUpdationWithNewDetailsResult.getUpdatedRoles().isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            } else if (rolesUpdationWithNewDetailsResult.getUpdatedRoles().isEmpty()) {
                mapOfErrors.remove("missing_permissions");
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No roles updated",
                            "reasons_due_to_which_roles_has_not_been_updated", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No roles updated"));
                }
            }
            if (!rolesUpdationWithNewDetailsResult.getRoleNamesOfRolesWeHaveToRemoveFromUsers().isEmpty()) {
                Collection<UUID> idsOfUsersWeHaveToRemoveTokens = dbServiceClient.getUserIdsByRoleNames(rolesUpdationWithNewDetailsResult.getRoleNamesOfRolesWeHaveToRemoveFromUsers());
                if (!idsOfUsersWeHaveToRemoveTokens.isEmpty()) {
                    authServiceClient.revokeTokensByUsersIds(idsOfUsersWeHaveToRemoveTokens);
                }
            }
            List<RoleSummaryDto> updatedRoles = new ArrayList<>();
            for (RoleModel role : dbServiceClient.updateRoles(rolesUpdationWithNewDetailsResult.getUpdatedRoles())) {
                updatedRoles.add(mapperUtility.toRoleSummaryDto(role));
            }
            mapOfErrors.remove("missing_permissions");
            if (isLenient &&
                    !mapOfErrors.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "updated_roles", updatedRoles,
                        "reasons_due_to_which_some_roles_has_not_been_updated", mapOfErrors
                ));
            }
            return ResponseEntity.ok(Map.of("updated_roles", updatedRoles));
        }
        throw new ServiceUnavailableException("Updating roles is currently disabled. Please try again later");
    }

    private void checkUserCanUpdateRoles(String updaterHighestTopRole) {
        if (updaterHighestTopRole == null && !unleash.isEnabled(ALLOW_UPDATE_ROLES_BY_USERS_HAVE_PERMISSION_TO_UPDATE_ROLES.name())) {
            throw new ServiceUnavailableException("Updating roles is currently disabled. Please try again later");
        }
    }

    private void validateDtosSizeForRolesUpdation(Variant variant,
                                                  Set<RoleCreationUpdationDto> dtos) {
        if (dtos.isEmpty()) {
            throw new SimpleBadRequestException("No roles to update");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxRolesToUpdateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxRolesToUpdateAtATime < 1) {
                maxRolesToUpdateAtATime = DEFAULT_MAX_ROLES_TO_UPDATE_AT_A_TIME;
            }
            if (dtos.size() > maxRolesToUpdateAtATime) {
                throw new SimpleBadRequestException("Cannot update more than " + maxRolesToUpdateAtATime + " roles at a time");
            }
        } else if (dtos.size() > DEFAULT_MAX_ROLES_TO_UPDATE_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot update more than " + DEFAULT_MAX_ROLES_TO_UPDATE_AT_A_TIME + " roles at a time");
        }
    }

    private RolesUpdationWithNewDetailsResultDto updateRolesWithNewDetails(Set<RoleCreationUpdationDto> dtos,
                                                                           Map<String, RoleModel> roleNameToRoleMap,
                                                                           Map<String, PermissionModel> resolvedPermissionsMap,
                                                                           String encryptedUpdaterUsername) throws Exception {
        Set<RoleModel> updatedRoles = new HashSet<>();
        Set<String> removeTokensForRoleNames = new HashSet<>();
        String decryptedUpdaterUsername = aesStaticEncryptorDecryptor.decrypt(encryptedUpdaterUsername);
        boolean isUpdated;
        boolean shouldRemoveTokens;
        for (RoleCreationUpdationDto dto : dtos) {
            RoleModel roleToUpdate = roleNameToRoleMap.get(dto.getRoleName());
            if (roleToUpdate == null) {
                continue;
            }
            isUpdated = false;
            shouldRemoveTokens = false;
            if (dto.getDescription() != null && !dto.getDescription().equals(roleToUpdate.getDescription())) {
                roleToUpdate.setDescription(dto.getDescription());
                isUpdated = true;
            }
            if (dto.getPermissions() != null) {
                if (dto.getPermissions().isEmpty()) {
                    if (!roleToUpdate.getPermissions().isEmpty()) {
                        roleToUpdate.getPermissions().clear();
                        isUpdated = true;
                        shouldRemoveTokens = true;
                    }
                } else {
                    Set<PermissionModel> permissionsToAssign = new HashSet<>();
                    for (String permissionName : dto.getPermissions()) {
                        PermissionModel permission = resolvedPermissionsMap.get(permissionName);
                        if (permission != null) {
                            permissionsToAssign.add(permission);
                        }
                    }
                    if (!roleToUpdate.getPermissions().equals(permissionsToAssign)) {
                        roleToUpdate.setPermissions(permissionsToAssign);
                        isUpdated = true;
                        shouldRemoveTokens = true;
                    }
                }
            }
            if (isUpdated) {
                roleToUpdate.recordUpdation(aesRandomEncryptorDecryptor.encrypt(decryptedUpdaterUsername));
                updatedRoles.add(roleToUpdate);
                if (shouldRemoveTokens) {
                    removeTokensForRoleNames.add(roleToUpdate.getRoleName());
                }
            }
        }
        return new RolesUpdationWithNewDetailsResultDto(updatedRoles, removeTokensForRoleNames);
    }

    public ResponseEntity<Map<String, Object>> readPermissions(Set<String> permissionNames,
                                                               String leniency,
                                                               HttpServletRequest request) throws Exception {
        Set<String> readerAuthorities = Set.of(request.getHeader(X_AUTHORITIES_HEADER).split(","));
        canReadPermissions(readerAuthorities);
        boolean isLenient = validateLeniency(leniency);
        String readerHighestTopRole = getUserHighestTopRole(readerAuthorities);
        Variant variant = unleash.getVariant(ALLOW_READ_PERMISSIONS.name());
        if (entryCheck(variant, readerHighestTopRole)) {
            checkUserCanReadPermissions(readerHighestTopRole);
            validateInputsSizeForPermissionsToRead(variant, permissionNames);
            Set<String> invalidInputs = new HashSet<>();
            permissionNames.remove(null);
            Iterator<String> iterator = permissionNames.iterator();
            String temp;
            while (iterator.hasNext()) {
                temp = iterator.next();
                try {
                    validateRoleNameOrPermissionName(temp, "Permission name");
                } catch (SimpleBadRequestException ex) {
                    invalidInputs.add(temp);
                    iterator.remove();
                }
            }
            Map<String, Object> mapOfErrors = new HashMap<>();
            if (!invalidInputs.isEmpty()) {
                mapOfErrors.put("invalid_permission_names", invalidInputs);
            }
            if (!isLenient) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.badRequest().body(mapOfErrors);
                } else if (permissionNames.isEmpty()) {
                    return ResponseEntity.ok(Map.of("message", "No permissions returned"));
                }
            } else if (permissionNames.isEmpty()) {
                if (!mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No permissions returned",
                            "reasons_due_to_which_permissions_has_not_been_returned", mapOfErrors
                    ));
                } else {
                    return ResponseEntity.ok(Map.of("message", "No permissions returned"));
                }
            }
            Collection<PermissionModel> permissions = dbServiceClient.getPermissionsByIdIn(permissionNames);
            for (PermissionModel permission : permissions) {
                permission.setCreatedBy(aesRandomEncryptorDecryptor.decrypt(permission.getCreatedBy()));
                permissionNames.remove(permission.getPermissionName());
            }
            if (!permissionNames.isEmpty()) {
                mapOfErrors.put("permissions_not_found", permissionNames);
            }
            if (!isLenient && !mapOfErrors.isEmpty()) {
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            if (permissions.isEmpty()) {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "message", "No permissions returned",
                            "reasons_due_to_which_permissions_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("message", "No permissions returned"));
            } else {
                if (isLenient && !mapOfErrors.isEmpty()) {
                    return ResponseEntity.ok(Map.of(
                            "found_permissions", permissions,
                            "reasons_due_to_which_some_permissions_has_not_been_returned", mapOfErrors
                    ));
                }
                return ResponseEntity.ok(Map.of("found_permissions", permissions));
            }
        }
        throw new ServiceUnavailableException("Reading permissions is currently disabled. Please try again later");
    }

    private void checkUserCanReadPermissions(String readerHighestTopRole) {
        if (readerHighestTopRole == null && !unleash.isEnabled(ALLOW_READ_PERMISSIONS_BY_USERS_HAVE_PERMISSION_TO_READ_PERMISSIONS.name())) {
            throw new ServiceUnavailableException("Reading permissions is currently disabled. Please try again later");
        }
    }

    private void validateInputsSizeForPermissionsToRead(Variant variant,
                                                        Set<String> permissionNames) {
        if (permissionNames.isEmpty()) {
            throw new SimpleBadRequestException("No permissions to read");
        }
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            int maxPermissionsToReadAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxPermissionsToReadAtATime < 1) {
                maxPermissionsToReadAtATime = DEFAULT_MAX_PERMISSIONS_TO_READ_AT_A_TIME;
            }
            if (permissionNames.size() > maxPermissionsToReadAtATime) {
                throw new SimpleBadRequestException("Cannot read more than " + maxPermissionsToReadAtATime + " permissions at a time");
            }
        } else if (permissionNames.size() > DEFAULT_MAX_PERMISSIONS_TO_READ_AT_A_TIME) {
            throw new SimpleBadRequestException("Cannot read more than " + DEFAULT_MAX_PERMISSIONS_TO_READ_AT_A_TIME + " permissions at a time");
        }
    }
}
