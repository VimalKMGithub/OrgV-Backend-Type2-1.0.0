package org.v.commons.utils;

import io.getunleash.Unleash;
import org.v.commons.exceptions.ServiceUnavailableException;
import org.v.commons.models.UserModel;

import static org.v.commons.enums.FeatureFlags.*;
import static org.v.commons.enums.MfaType.AUTHENTICATOR_APP_MFA;
import static org.v.commons.enums.MfaType.EMAIL_MFA;

public class UnleashServiceUtility {
    public static boolean shouldDoMfa(UserModel user,
                                      Unleash unleash) {
        boolean doMfa = false;
        if (user.isMfaEnabled() && !user.getMfaMethods().isEmpty()) {
            boolean unleashEmailMfa = unleash.isEnabled(MFA_EMAIL.name());
            boolean unleashAuthenticatorAppMfa = unleash.isEnabled(MFA_AUTHENTICATOR_APP.name());
            if (unleashEmailMfa && user.hasMfaMethod(EMAIL_MFA)) {
                doMfa = true;
            } else if (unleashAuthenticatorAppMfa && user.hasMfaMethod(AUTHENTICATOR_APP_MFA)) {
                doMfa = true;
            }
        }
        return doMfa;
    }

    public static void checkMfaGloballyEnabled(Unleash unleash) {
        if (!unleash.isEnabled(MFA.name())) {
            throw new ServiceUnavailableException("Mfa is disabled globally");
        }
    }
}
