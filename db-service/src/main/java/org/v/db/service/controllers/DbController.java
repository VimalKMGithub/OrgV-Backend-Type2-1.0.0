package org.v.db.service.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.v.db.service.models.ExternalIdentityModel;
import org.v.db.service.models.PermissionModel;
import org.v.db.service.models.RoleModel;
import org.v.db.service.models.UserModel;
import org.v.db.service.services.DbService;

import java.util.Collection;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class DbController {
    private final DbService dbService;

    @PostMapping("/user")
    public UserModel createUser(@RequestBody UserModel user) {
        return dbService.createUser(user);
    }

    @PutMapping("/user")
    public UserModel updateUser(@RequestBody UserModel user) {
        return createUser(user);
    }

    @GetMapping("/user/exists-by-username")
    public boolean existsByUsername(@RequestParam String username) {
        return dbService.existsByUsername(username);
    }

    @GetMapping("/user/exists-by-email")
    public boolean existsByEmail(@RequestParam String email) {
        return dbService.existsByEmail(email);
    }

    @GetMapping("/user/exists-by-real-email")
    public boolean existsByRealEmail(@RequestParam String realEmail) {
        return dbService.existsByRealEmail(realEmail);
    }

    @GetMapping("/user/by-id")
    public UserModel getUserById(@RequestParam UUID id) {
        return dbService.getUserById(id);
    }

    @GetMapping("/user/by-username")
    public UserModel getUserByUsername(@RequestParam String username) {
        return dbService.getUserByUsername(username);
    }

    @GetMapping("/user/by-email")
    public UserModel getUserByEmail(@RequestParam String email) {
        return dbService.getUserByEmail(email);
    }

    @PostMapping("/users/by-username-in")
    public Collection<UserModel> getUsersByUsernameIn(@RequestBody Collection<String> usernames) {
        return dbService.getUsersByUsernameIn(usernames);
    }

    @PostMapping("/users/by-email-in")
    public Collection<UserModel> getUsersByEmailIn(@RequestBody Collection<String> emails) {
        return dbService.getUsersByEmailIn(emails);
    }

    @PostMapping("/users/by-id-in")
    public Collection<UserModel> getUsersByIdIn(@RequestBody Collection<UUID> ids) {
        return dbService.getUsersByIdIn(ids);
    }

    @PostMapping("/users")
    public Collection<UserModel> createUsers(@RequestBody Collection<UserModel> users) {
        return dbService.createUsers(users);
    }

    @PutMapping("/users")
    public Collection<UserModel> updateUsers(@RequestBody Collection<UserModel> users) {
        return createUsers(users);
    }

    @DeleteMapping("/users")
    public void deleteUsers(@RequestBody Collection<UserModel> users) {
        dbService.deleteUsers(users);
    }

    @PostMapping("/roles/by-id-in")
    public Collection<RoleModel> getRolesByIdIn(@RequestBody Collection<String> ids) {
        return dbService.getRolesByIdIn(ids);
    }

    @PostMapping("/roles")
    public Collection<RoleModel> createRoles(@RequestBody Collection<RoleModel> roles) {
        return dbService.createRoles(roles);
    }

    @PostMapping("/permissions/by-id-in")
    public Collection<PermissionModel> getPermissionsByIdIn(@RequestBody Collection<String> ids) {
        return dbService.getPermissionsByIdIn(ids);
    }

    @DeleteMapping("/user-roles/by-role-names")
    public void deleteUserRolesByRoleNames(@RequestBody Collection<String> roleNames) {
        dbService.deleteUserRolesByRoleNames(roleNames);
    }

    @PostMapping("/user-ids/by-role-names")
    public Collection<UUID> getUserIdsByRoleNames(@RequestBody Collection<String> roleNames) {
        return dbService.getUserIdsByRoleNames(roleNames);
    }

    @DeleteMapping("/roles")
    public void deleteRoles(@RequestBody Collection<RoleModel> roles) {
        dbService.deleteRoles(roles);
    }

    @PutMapping("/roles")
    public Collection<RoleModel> updateRoles(@RequestBody Collection<RoleModel> roles) {
        return createRoles(roles);
    }

    @GetMapping("/external-identity/by-provider-and-provider-user-id")
    public ExternalIdentityModel getExternalIdentityByProviderAndProviderUserId(@RequestParam String provider,
                                                                                @RequestParam String providerUserId) {
        return dbService.getExternalIdentityByProviderAndProviderUserId(provider, providerUserId);
    }

    @PostMapping("/external-identity")
    public ExternalIdentityModel createExternalIdentity(@RequestBody ExternalIdentityModel identity) {
        return dbService.createExternalIdentity(identity);
    }

    @PutMapping("/external-identity")
    public ExternalIdentityModel updateExternalIdentity(@RequestBody ExternalIdentityModel identity) {
        return createExternalIdentity(identity);
    }

    @GetMapping("/user/by-real-email")
    public UserModel getUserByRealEmail(@RequestParam String realEmail) {
        return dbService.getUserByRealEmail(realEmail);
    }

    @GetMapping("/external-identity/exists-by-email")
    public boolean externalIdentityExistsByEmail(@RequestParam String email) {
        return dbService.externalIdentityExistsByEmail(email);
    }
}
