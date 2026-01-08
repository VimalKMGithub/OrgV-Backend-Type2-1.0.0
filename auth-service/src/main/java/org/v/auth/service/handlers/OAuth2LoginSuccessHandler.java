package org.v.auth.service.handlers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.v.auth.service.utils.AccessTokenUtility;
import org.v.commons.classes.MutableHttpServletRequest;
import org.v.commons.clients.DbServiceClient;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.encryptordecryptors.AesStaticEncryptorDecryptor;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.models.ExternalIdentityModel;
import org.v.commons.models.UserModel;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.v.auth.service.utils.AccessTokenUtility.ACCESS_TOKEN_EXPIRES_IN_SECONDS;
import static org.v.auth.service.utils.AccessTokenUtility.REFRESH_TOKEN_EXPIRES_IN_SECONDS;
import static org.v.commons.constants.HeadersCookies.*;
import static org.v.commons.utils.CookieUtility.*;
import static org.v.commons.utils.MailUtility.normalizeEmail;
import static org.v.commons.utils.UserUtility.*;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final DbServiceClient dbServiceClient;
    private final AccessTokenUtility accessTokenUtility;
    private final AesStaticEncryptorDecryptor aesStaticEncryptorDecryptor;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;
    private final PasswordEncoder passwordEncoder;
    private static final Set<String> ALLOWED_REDIRECT_ORIGINS = Set.of("http://localhost:9225", "http://localhost:9250", "http://localhost:9275");
    private static final Set<String> ALLOWED_CALLBACK_PATHS = Set.of("/oauth2/callback");

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        @NonNull Authentication authentication) throws IOException {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token) || oauth2Token.getPrincipal() == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication type");
            return;
        }
        String frontendRedirectUri = (String) request.getSession().getAttribute("FRONTEND_REDIRECT_URI");
        if (frontendRedirectUri == null || frontendRedirectUri.isBlank()) {
            throw new SimpleBadRequestException("Frontend redirect URI is required");
        }
        URI uri;
        try {
            uri = URI.create(frontendRedirectUri);
        } catch (Exception ex) {
            throw new SimpleBadRequestException("Malformed frontend redirect URI");
        }
        String origin = uri.getScheme() + "://" + uri.getAuthority();
        String path = uri.getPath();
        if (!ALLOWED_REDIRECT_ORIGINS.contains(origin)) {
            throw new SimpleBadRequestException("Invalid frontend redirect origin");
        }
        if (!ALLOWED_CALLBACK_PATHS.contains(path)) {
            throw new SimpleBadRequestException("Invalid frontend redirect path");
        }
        request.changeSessionId();
        request.getSession().removeAttribute("FRONTEND_REDIRECT_URI");
        String provider = oauth2Token.getAuthorizedClientRegistrationId().toLowerCase();
        Map<String, Object> attributes = oauth2Token.getPrincipal().getAttributes();
        String providerUserId;
        String email;
        String firstName;
        String lastName;
        String pictureUrl;
        switch (provider) {
            case "google" -> {
                providerUserId = (String) attributes.get("sub");
                email = (String) attributes.get("email");
                firstName = (String) attributes.get("given_name");
                lastName = (String) attributes.get("family_name");
                pictureUrl = (String) attributes.get("picture");
            }
            case "github" -> {
                providerUserId = String.valueOf(attributes.get("id"));
                email = (String) attributes.get("email");
                firstName = (String) attributes.get("login");
                lastName = "";
                pictureUrl = (String) attributes.get("avatar_url");
            }
            default -> {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unsupported OAuth2 provider");
                return;
            }
        }
        String deviceId = getCookieValue(request, X_DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "X-Device-Id cookie is required");
            return;
        }
        MutableHttpServletRequest wrappedRequest = new MutableHttpServletRequest(request);
        wrappedRequest.putHeader(X_DEVICE_ID_HEADER, deviceId);
        try {
            ExternalIdentityModel identity = dbServiceClient.getExternalIdentityByProviderAndProviderUserId(
                    aesStaticEncryptorDecryptor.encrypt(provider),
                    aesStaticEncryptorDecryptor.encrypt(providerUserId)
            );
            UserModel user;
            if (identity != null) {
                user = dbServiceClient.getUserById(identity.getUserId());
                identity.setLastUsedAt(Instant.now());
                dbServiceClient.updateExternalIdentity(identity);
            } else {
                String encryptedRealEmail = aesStaticEncryptorDecryptor.encrypt(
                        email != null ? normalizeEmail(email) : providerUserId + "@noemail." + provider
                );
                user = dbServiceClient.getUserByRealEmail(encryptedRealEmail);
                if (user == null) {
                    user = dbServiceClient.createUser(toUserModel(
                            provider + "_" + providerUserId,
                            encryptedRealEmail,
                            firstName,
                            lastName,
                            provider
                    ));
                }
                dbServiceClient.createExternalIdentity(toExternalIdentityModel(
                        provider,
                        providerUserId,
                        user.getId(),
                        encryptedRealEmail,
                        pictureUrl
                ));
            }
            user = dbServiceClient.getUserById(user.getId());
            response.setContentType("application/json");
            checkDeletedStatus(user);
            checkEnabledStatus(user);
            checkLockedStatus(user);
            checkExpiredStatus(user);
            Map<String, Object> tokens = accessTokenUtility.generateTokens(user, wrappedRequest);
            addHttpOnlyCookie(
                    response,
                    ACCESS_TOKEN_COOKIE,
                    (String) tokens.get("access_token"),
                    "Lax",
                    "/",
                    ACCESS_TOKEN_EXPIRES_IN_SECONDS
            );
            addHttpOnlyCookie(
                    response,
                    REFRESH_TOKEN_COOKIE,
                    (String) tokens.get("refresh_token"),
                    "Lax",
                    "/auth-service/",
                    REFRESH_TOKEN_EXPIRES_IN_SECONDS
            );
            response.sendRedirect(frontendRedirectUri);
        } catch (Exception ex) {
            response.sendRedirect(frontendRedirectUri + "?error=" + URLEncoder.encode(ex.getMessage(), StandardCharsets.UTF_8));
        } finally {
            removeHttpOnlyCookie(response, X_DEVICE_ID_HEADER, "Lax", "/");
        }
    }

    private UserModel toUserModel(String username,
                                  String encryptedRealEmail,
                                  String firstName,
                                  String lastName,
                                  String provider) throws Exception {
        return UserModel.builder()
                .username(aesStaticEncryptorDecryptor.encrypt(username))
                .email(encryptedRealEmail)
                .realEmail(encryptedRealEmail)
                .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                .firstName(firstName)
                .lastName(lastName)
                .oauth2User(true)
                .emailVerified(true)
                .createdBy(aesRandomEncryptorDecryptor.encrypt(provider))
                .build();
    }

    private ExternalIdentityModel toExternalIdentityModel(String provider,
                                                          String providerUserId,
                                                          UUID userId,
                                                          String encryptedRealEmail,
                                                          String profilePictureUrl) throws Exception {
        return ExternalIdentityModel.builder()
                .provider(aesStaticEncryptorDecryptor.encrypt(provider))
                .providerUserId(aesStaticEncryptorDecryptor.encrypt(providerUserId))
                .email(encryptedRealEmail)
                .userId(userId)
                .lastUsedAt(Instant.now())
                .profilePictureUrl(profilePictureUrl == null
                        ? null
                        : aesRandomEncryptorDecryptor.encrypt(profilePictureUrl))
                .build();
    }
}
