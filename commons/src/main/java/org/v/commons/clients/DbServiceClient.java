package org.v.commons.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import org.v.commons.config.FeignConfig;
import org.v.commons.models.ExternalIdentityModel;
import org.v.commons.models.PermissionModel;
import org.v.commons.models.RoleModel;
import org.v.commons.models.UserModel;

import java.util.Collection;
import java.util.UUID;

@FeignClient(name = "db-service", configuration = FeignConfig.class)
public interface DbServiceClient {
    @PostMapping("/user")
    UserModel createUser(@RequestBody UserModel user);

    @PutMapping("/user")
    UserModel updateUser(@RequestBody UserModel user);

    @GetMapping("/user/exists-by-username")
    boolean existsByUsername(@RequestParam String username);

    @GetMapping("/user/exists-by-email")
    boolean existsByEmail(@RequestParam String email);

    @GetMapping("/user/exists-by-real-email")
    boolean existsByRealEmail(@RequestParam String realEmail);

    @GetMapping("/user/by-id")
    UserModel getUserById(@RequestParam UUID id);

    @GetMapping("/user/by-username")
    UserModel getUserByUsername(@RequestParam String username);

    @GetMapping("/user/by-email")
    UserModel getUserByEmail(@RequestParam String email);

    @PostMapping("/users/by-username-in")
    Collection<UserModel> getUsersByUsernameIn(@RequestBody Collection<String> usernames);

    @PostMapping("/users/by-email-in")
    Collection<UserModel> getUsersByEmailIn(@RequestBody Collection<String> emails);

    @PostMapping("/users/by-id-in")
    Collection<UserModel> getUsersByIdIn(@RequestBody Collection<UUID> ids);

    @PostMapping("/users")
    Collection<UserModel> createUsers(@RequestBody Collection<UserModel> users);

    @PutMapping("/users")
    Collection<UserModel> updateUsers(@RequestBody Collection<UserModel> users);

    @DeleteMapping("/users")
    void deleteUsers(@RequestBody Collection<UserModel> users);

    @PostMapping("/roles/by-id-in")
    Collection<RoleModel> getRolesByIdIn(@RequestBody Collection<String> ids);

    @PostMapping("/roles")
    Collection<RoleModel> createRoles(@RequestBody Collection<RoleModel> roles);

    @PostMapping("/permissions/by-id-in")
    Collection<PermissionModel> getPermissionsByIdIn(@RequestBody Collection<String> ids);

    @DeleteMapping("/user-roles/by-role-names")
    void deleteUserRolesByRoleNames(@RequestBody Collection<String> roleNames);

    @PostMapping("/user-ids/by-role-names")
    Collection<UUID> getUserIdsByRoleNames(@RequestBody Collection<String> roleNames);

    @DeleteMapping("/roles")
    void deleteRoles(@RequestBody Collection<RoleModel> roles);

    @PutMapping("/roles")
    Collection<RoleModel> updateRoles(@RequestBody Collection<RoleModel> roles);

    @GetMapping("/external-identity/by-provider-and-provider-user-id")
    ExternalIdentityModel getExternalIdentityByProviderAndProviderUserId(@RequestParam String provider,
                                                                         @RequestParam String providerUserId);

    @PostMapping("/external-identity")
    ExternalIdentityModel createExternalIdentity(@RequestBody ExternalIdentityModel identity);

    @PutMapping("/external-identity")
    ExternalIdentityModel updateExternalIdentity(@RequestBody ExternalIdentityModel identity);

    @GetMapping("/user/by-real-email")
    UserModel getUserByRealEmail(@RequestParam String realEmail);

    @GetMapping("/external-identity/exists-by-email")
    boolean externalIdentityExistsByEmail(@RequestParam String email);
}
