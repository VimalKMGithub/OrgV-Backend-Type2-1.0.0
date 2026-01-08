package org.v.commons.utils;

import org.v.commons.exceptions.SimpleBadRequestException;

import java.util.Set;

public class ToggleUtility {
    public static final String DEFAULT_TOGGLE = "disable";
    public static final Set<String> TOGGLE_TYPES = Set.of("enable", "disable");

    public static boolean isToggleExists(String toggle) {
        return TOGGLE_TYPES.contains(toggle.toLowerCase());
    }

    public static boolean getToggleAsBoolean(String toggle) {
        if (!isToggleExists(toggle)) {
            throw new SimpleBadRequestException("Unsupported toggle type: " + toggle + ". Supported values: " + TOGGLE_TYPES);
        }
        return toggle.equalsIgnoreCase("enable");
    }
}
