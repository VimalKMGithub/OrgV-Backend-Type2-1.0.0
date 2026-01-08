package org.v.db.service.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.v.db.service.models.ExternalIdentityModel;
import org.v.db.service.models.PermissionModel;
import org.v.db.service.models.RoleModel;
import org.v.db.service.models.UserModel;
import org.v.db.service.repos.ExternalIdentityRepo;
import org.v.db.service.repos.PermissionRepo;
import org.v.db.service.repos.RoleRepo;
import org.v.db.service.repos.UserRepo;

import java.util.Collection;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DbService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final ExternalIdentityRepo externalIdentityRepo;

    public UserModel createUser(UserModel user) {
        return userRepo.save(user);
    }

    public boolean existsByUsername(String username) {
        return userRepo.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepo.existsByEmail(email);
    }

    public boolean existsByRealEmail(String realEmail) {
        return userRepo.existsByRealEmail(realEmail);
    }

    public UserModel getUserById(UUID id) {
        return userRepo.findById(id).orElse(null);
    }

    public UserModel getUserByUsername(String username) {
        return userRepo.findByUsername(username);
    }

    public UserModel getUserByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    public Collection<UserModel> getUsersByUsernameIn(Collection<String> usernames) {
        return userRepo.findByUsernameIn(usernames);
    }

    public Collection<UserModel> getUsersByEmailIn(Collection<String> emails) {
        return userRepo.findByEmailIn(emails);
    }

    public Collection<UserModel> getUsersByIdIn(Collection<UUID> ids) {
        return userRepo.findAllById(ids);
    }

    public Collection<UserModel> createUsers(Collection<UserModel> users) {
        return userRepo.saveAll(users);
    }

    public void deleteUsers(Collection<UserModel> users) {
        userRepo.deleteAll(users);
    }

    public Collection<RoleModel> getRolesByIdIn(Collection<String> ids) {
        return roleRepo.findAllById(ids);
    }

    public Collection<RoleModel> createRoles(Collection<RoleModel> roles) {
        return roleRepo.saveAll(roles);
    }

    public Collection<PermissionModel> getPermissionsByIdIn(Collection<String> ids) {
        return permissionRepo.findAllById(ids);
    }

    public void deleteUserRolesByRoleNames(Collection<String> roleNames) {
        roleRepo.deleteUserRolesByRoleNames(roleNames);
    }

    public Collection<UUID> getUserIdsByRoleNames(Collection<String> roleNames) {
        return roleRepo.getUserIdsByRoleNames(roleNames);
    }

    public void deleteRoles(Collection<RoleModel> roles) {
        roleRepo.deleteAll(roles);
    }

    public ExternalIdentityModel getExternalIdentityByProviderAndProviderUserId(String provider,
                                                                                String providerUserId) {
        return externalIdentityRepo.findByProviderAndProviderUserId(provider, providerUserId);
    }

    public ExternalIdentityModel createExternalIdentity(ExternalIdentityModel identity) {
        return externalIdentityRepo.save(identity);
    }

    public UserModel getUserByRealEmail(String realEmail) {
        return userRepo.findByRealEmail(realEmail);
    }

    public boolean externalIdentityExistsByEmail(String email) {
        return externalIdentityRepo.existsByEmail(email);
    }
}
