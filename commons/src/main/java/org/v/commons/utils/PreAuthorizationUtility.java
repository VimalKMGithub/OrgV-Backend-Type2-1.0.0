package org.v.commons.utils;

import org.v.commons.exceptions.AccessDeniedException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.v.commons.enums.SystemPermissions.*;
import static org.v.commons.enums.SystemRoles.TOP_ROLES;

public class PreAuthorizationUtility {
    private static final Set<String> TOP_ROLES_SET = topRolesSet();
    private static final Set<String> CAN_CREATE_USERS_SET = canCreateUsersSet();
    private static final Set<String> CAN_READ_USERS_SET = canReadUsersSet();
    private static final Set<String> CAN_UPDATE_USERS_SET = canUpdateUsersSet();
    private static final Set<String> CAN_DELETE_USERS_SET = canDeleteUsersSet();
    private static final Set<String> CAN_READ_PERMISSIONS_SET = canReadPermissionsSet();
    private static final Set<String> CAN_CREATE_ROLES_SET = canCreateRolesSet();
    private static final Set<String> CAN_READ_ROLES_SET = canReadRolesSet();
    private static final Set<String> CAN_UPDATE_ROLES_SET = canUpdateRolesSet();
    private static final Set<String> CAN_DELETE_ROLES_SET = canDeleteRolesSet();

    private static Set<String> topRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES);
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_CREATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_UPDATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteUsersSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_DELETE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadPermissionsSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_PERMISSION.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_CREATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_READ_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_UPDATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteRolesSet() {
        Set<String> set = new HashSet<>(TOP_ROLES_SET);
        set.add(CAN_DELETE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    public static void canCreateUsers(Set<String> userAuthorities) {
        if (!containsAny(CAN_CREATE_USERS_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to create users");
        }
    }

    public static void canReadUsers(Set<String> userAuthorities) {
        if (!containsAny(CAN_READ_USERS_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to read users");
        }
    }

    public static void canUpdateUsers(Set<String> userAuthorities) {
        if (!containsAny(CAN_UPDATE_USERS_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to update users");
        }
    }

    public static void canDeleteUsers(Set<String> userAuthorities) {
        if (!containsAny(CAN_DELETE_USERS_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to delete users");
        }
    }

    public static void canReadPermissions(Set<String> userAuthorities) {
        if (!containsAny(CAN_READ_PERMISSIONS_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to read permissions");
        }
    }

    public static void canCreateRoles(Set<String> userAuthorities) {
        if (!containsAny(CAN_CREATE_ROLES_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to create roles");
        }
    }

    public static void canReadRoles(Set<String> userAuthorities) {
        if (!containsAny(CAN_READ_ROLES_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to read roles");
        }
    }

    public static void canUpdateRoles(Set<String> userAuthorities) {
        if (!containsAny(CAN_UPDATE_ROLES_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to update roles");
        }
    }

    public static void canDeleteRoles(Set<String> userAuthorities) {
        if (!containsAny(CAN_DELETE_ROLES_SET, userAuthorities)) {
            throw new AccessDeniedException("Not allowed to delete roles");
        }
    }

    private static boolean containsAny(Set<String> requiredAuthorities,
                                       Set<String> userAuthorities) {
        for (String userPermission : userAuthorities) {
            if (requiredAuthorities.contains(userPermission)) {
                return true;
            }
        }
        return false;
    }
}
