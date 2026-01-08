package org.v.auth.service.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.v.auth.service.services.TokenService;
import org.v.commons.dtos.AccessTokenRequestDto;
import org.v.commons.dtos.AuthenticationDto;
import org.v.commons.models.UserModel;

import java.util.Set;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/verify-token")
    public AuthenticationDto verifyToken(@RequestBody AccessTokenRequestDto accessTokenRequest,
                                         HttpServletRequest request) throws Exception {
        return tokenService.verifyAccessToken(accessTokenRequest.getAccessToken(), request);
    }

    @PostMapping("/revoke-tokens")
    public void revokeTokens(@RequestBody Set<UserModel> users) throws Exception {
        tokenService.revokeTokens(users);
    }

    @PostMapping("/revoke-tokens-by-users-ids")
    public void revokeTokensByUsersIds(@RequestBody Set<UUID> usersIds) throws Exception {
        tokenService.revokeTokensByUsersIds(usersIds);
    }
}
