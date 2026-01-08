package org.v.gateway.service.constants;

import java.util.Set;

public class PublicEndpoints {
    private static final String USER_SERVICE = "/user-service";
    private static final String AUTH_SERVICE = "/auth-service";
    public static final Set<String> PUBLIC_GATEWAY_ENDPOINTS_SET = Set.of(
            "/csrf",
            "/csp-report"
    );
    public static final Set<String> PUBLIC_ENDPOINTS_SET = Set.of(
            USER_SERVICE + "/register",
            USER_SERVICE + "/verify-email",
            USER_SERVICE + "/resend-email-verification-link",
            USER_SERVICE + "/forgot-password",
            USER_SERVICE + "/forgot-password-method-selection",
            USER_SERVICE + "/reset-password",

            AUTH_SERVICE + "/login",
            AUTH_SERVICE + "/refresh-access-token",
            AUTH_SERVICE + "/revoke-refresh-token",
            AUTH_SERVICE + "/request-to-login-by-mfa",
            AUTH_SERVICE + "/verify-to-login-by-mfa",
            AUTH_SERVICE + "/oauth2/authorization/google",
            AUTH_SERVICE + "/login/oauth2/code/google",
            AUTH_SERVICE + "/oauth2/authorization/github",
            AUTH_SERVICE + "/login/oauth2/code/github"
    );
}
