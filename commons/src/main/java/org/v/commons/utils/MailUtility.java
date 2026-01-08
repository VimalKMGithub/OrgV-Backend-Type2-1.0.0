package org.v.commons.utils;

import org.v.commons.enums.MailType;

import java.util.Set;

import static org.v.commons.utils.MailTemplateUtility.*;

public class MailUtility {
    private static final Set<String> REMOVE_DOTS = Set.of(
            "gmail.com",
            "googlemail.com"
    );
    private static final Set<String> REMOVE_ALIAS_PART = Set.of(
            "gmail.com",
            "googlemail.com",
            "live.com",
            "protonmail.com",
            "hotmail.com",
            "outlook.com"
    );

    public static String normalizeEmail(String email) {
        String lowerCasedEmail = email.trim().toLowerCase();
        int atIndex = lowerCasedEmail.indexOf('@');
        String local = lowerCasedEmail.substring(0, atIndex);
        String domain = lowerCasedEmail.substring(atIndex + 1);
        if (REMOVE_DOTS.contains(domain)) {
            local = local.replace(".", "");
        }
        if (REMOVE_ALIAS_PART.contains(domain)) {
            int plusIndex = local.indexOf('+');
            if (plusIndex != -1) {
                local = local.substring(0, plusIndex);
            }
        }
        return local + "@" + domain;
    }

    public static String getEmailText(String value,
                                      MailType mailType) {
        return switch (mailType) {
            case OTP -> String.format(OTP_TEMPLATE, value);
            case LINK -> String.format(LINK_TEMPLATE, value);
            case ACCOUNT_DELETION_CONFIRMATION -> ACCOUNT_DELETION_CONFIRMATION_TEMPLATE;
            case PASSWORD_RESET_CONFIRMATION -> PASSWORD_RESET_CONFIRMATION_TEMPLATE;
            case SELF_PASSWORD_CHANGE_CONFIRMATION -> SELF_PASSWORD_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_EMAIL_CHANGE_CONFIRMATION -> SELF_EMAIL_CHANGE_CONFIRMATION_TEMPLATE;
            case SELF_UPDATE_DETAILS_CONFIRMATION -> SELF_UPDATE_DETAILS_CONFIRMATION_TEMPLATE;
            case SELF_MFA_ENABLE_DISABLE_CONFIRMATION ->
                    String.format(SELF_MFA_ENABLE_DISABLE_CONFIRMATION_TEMPLATE, value);
            case NEW_SIGN_IN_CONFIRMATION -> NEW_SIGN_IN_CONFIRMATION_TEMPLATE;
            case SUSPICIOUS_ACTIVITY_CONFIRMATION -> String.format(SUSPICIOUS_ACTIVITY_CONFIRMATION_TEMPLATE, value);
        };
    }
}
