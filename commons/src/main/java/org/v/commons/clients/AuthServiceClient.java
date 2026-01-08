package org.v.commons.clients;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.v.commons.config.FeignConfig;
import org.v.commons.dtos.AccessTokenRequestDto;
import org.v.commons.dtos.AuthenticationDto;
import org.v.commons.models.UserModel;

import java.util.Collection;
import java.util.UUID;

import static org.v.commons.constants.HeadersCookies.USER_AGENT_HEADER;
import static org.v.commons.constants.HeadersCookies.X_DEVICE_ID_HEADER;

@FeignClient(name = "auth-service", configuration = FeignConfig.class)
public interface AuthServiceClient {
    @PostMapping("/verify-token")
    AuthenticationDto verifyToken(
            @RequestBody AccessTokenRequestDto accessTokenRequest,
            @RequestHeader(USER_AGENT_HEADER) String userAgent,
            @RequestHeader(X_DEVICE_ID_HEADER) String deviceId
    );

    @PostMapping("/revoke-tokens")
    void revokeTokens(@RequestBody Collection<UserModel> users);

    @PostMapping("/revoke-tokens-by-users-ids")
    void revokeTokensByUsersIds(@RequestBody Collection<UUID> usersIds);
}
