package org.v.commons.utils;

import org.v.commons.enums.MfaType;
import org.v.commons.exceptions.SimpleBadRequestException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class MfaUtility {
    public static final Set<String> MFA_METHODS = buildMfaMethodsSet();

    private static Set<String> buildMfaMethodsSet() {
        Set<String> methods = new HashSet<>();
        for (MfaType type : MfaType.values()) {
            methods.add(type.name().toLowerCase());
        }
        return Collections.unmodifiableSet(methods);
    }

    private static boolean isMfaExists(String type) {
        return MFA_METHODS.contains(type.toLowerCase());
    }

    public static MfaType getMfaType(String type) {
        if (!isMfaExists(type)) {
            throw new SimpleBadRequestException("Unsupported Mfa type: " + type + ". Supported types: " + MFA_METHODS);
        }
        return MfaType.valueOf(type.toUpperCase());
    }
}
