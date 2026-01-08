package org.v.auth.service.services;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.v.auth.service.utils.AccessTokenUtility;
import org.v.commons.dtos.AuthenticationDto;
import org.v.commons.models.UserModel;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final AccessTokenUtility accessTokenUtility;

    public AuthenticationDto verifyAccessToken(String accessToken,
                                               HttpServletRequest request) throws Exception {
        return accessTokenUtility.verifyAccessToken(accessToken, request);
    }

    public void revokeTokens(Set<UserModel> users) throws Exception {
        accessTokenUtility.revokeTokens(users);
    }

    public void revokeTokensByUsersIds(Set<UUID> usersIds) throws Exception {
        accessTokenUtility.revokeTokensByUsersIds(usersIds);
    }
}
