package org.v.auth.service.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.v.auth.service.dtos.LoginMfaRequestDto;
import org.v.auth.service.dtos.LoginRequestDto;
import org.v.auth.service.dtos.ToggleMfaRequestDto;
import org.v.auth.service.services.AuthService;

import java.util.Map;
import java.util.Set;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequestDto loginRequest,
                                                     HttpServletRequest request,
                                                     HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.login(loginRequest.getUsernameOrEmailOrId(), loginRequest.getPassword(), request, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.logout(request, response));
    }

    @PostMapping("/logout-from-devices")
    public ResponseEntity<Map<String, String>> logoutFromDevices(@RequestBody Set<String> deviceIds,
                                                                 HttpServletRequest request,
                                                                 HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.logoutFromDevices(deviceIds, request, response));
    }

    @PostMapping("/logout-all-devices")
    public ResponseEntity<Map<String, String>> logoutAllDevices(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.logoutAllDevices(request, response));
    }

    @PostMapping("/refresh-access-token")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.refreshAccessToken(request, response));
    }

    @PostMapping("/revoke-access-token")
    public ResponseEntity<Map<String, String>> revokeAccessToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.revokeAccessToken(request, response));
    }

    @PostMapping("/revoke-refresh-token")
    public ResponseEntity<Map<String, String>> revokeRefreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.revokeRefreshToken(request, response));
    }

    @PostMapping("/request-to-toggle-mfa")
    public ResponseEntity<Object> requestToToggleMfa(@RequestBody ToggleMfaRequestDto toggleMfaRequest,
                                                     HttpServletRequest request) throws Exception {
        return authService.requestToToggleMfa(toggleMfaRequest.getType(), toggleMfaRequest.getToggle(), request);
    }

    @PostMapping("/verify-to-toggle-mfa")
    public ResponseEntity<Map<String, String>> verifyToggleMfa(@RequestBody ToggleMfaRequestDto toggleMfaRequest,
                                                               HttpServletRequest request,
                                                               HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.verifyToggleMfa(toggleMfaRequest.getType(), toggleMfaRequest.getToggle(), toggleMfaRequest.getOtpTotp(), request, response));
    }

    @PostMapping("/request-to-login-by-mfa")
    public ResponseEntity<Map<String, String>> requestToLoginByMfa(@RequestBody LoginMfaRequestDto loginMfaRequest) throws Exception {
        return ResponseEntity.ok(authService.requestToLoginByMfa(loginMfaRequest.getType(), loginMfaRequest.getStateToken()));
    }

    @PostMapping("/verify-to-login-by-mfa")
    public ResponseEntity<Map<String, Object>> verifyMfaToLogin(@RequestBody LoginMfaRequestDto loginMfaRequest,
                                                                HttpServletRequest request,
                                                                HttpServletResponse response) throws Exception {
        return ResponseEntity.ok(authService.verifyMfaToLogin(loginMfaRequest.getType(), loginMfaRequest.getStateToken(), loginMfaRequest.getOtpTotp(), request, response));
    }

    @GetMapping("/active-devices")
    public ResponseEntity<Map<Object, Object>> getActiveDevices(HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(authService.getActiveDevices(request));
    }
}
