package org.v.user.service.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.v.commons.dtos.RegistrationDto;
import org.v.commons.dtos.ResetPasswordDto;
import org.v.commons.dtos.UserSummaryDto;
import org.v.user.service.dtos.*;
import org.v.user.service.services.UserService;

import java.util.Map;

import static org.v.commons.enums.MfaType.DEFAULT_MFA;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegistrationDto dto) throws Exception {
        return userService.register(dto);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, Object>> verifyEmail(@RequestBody EmailVerificationTokenRequestDto emailVerificationTokenRequest) throws Exception {
        return ResponseEntity.ok(userService.verifyEmail(emailVerificationTokenRequest.getEmailVerificationToken()));
    }

    @PostMapping("/resend-email-verification-link")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLink(@RequestBody UsernameOrEmailOrIdRequestDto usernameOrEmailOrIdRequest) throws Exception {
        return ResponseEntity.ok(userService.resendEmailVerificationLink(usernameOrEmailOrIdRequest.getUsernameOrEmailOrId()));
    }

    @GetMapping("/self-details")
    public ResponseEntity<UserSummaryDto> selfDetails(HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.selfDetails(request));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, Object>> forgotPassword(@RequestBody UsernameOrEmailOrIdRequestDto usernameOrEmailOrIdRequest) throws Exception {
        return userService.forgotPassword(usernameOrEmailOrIdRequest.getUsernameOrEmailOrId());
    }

    @PostMapping("/forgot-password-method-selection")
    public ResponseEntity<Map<String, String>> forgotPasswordMethodSelection(@RequestBody UsernameOrEmailOrIdRequestDto usernameOrEmailOrIdRequest,
                                                                             @RequestParam(defaultValue = DEFAULT_MFA) String method) throws Exception {
        return ResponseEntity.ok(userService.forgotPasswordMethodSelection(usernameOrEmailOrIdRequest.getUsernameOrEmailOrId(), method));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody ResetPasswordDto dto) throws Exception {
        return userService.resetPassword(dto);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Map<String, Object>> changePassword(@RequestBody ChangePasswordDto dto,
                                                              HttpServletRequest request) throws Exception {
        return userService.changePassword(dto, request);
    }

    @PostMapping("/change-password-method-selection")
    public ResponseEntity<Map<String, String>> changePasswordMethodSelection(@RequestParam String method,
                                                                             HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.changePasswordMethodSelection(method, request));
    }

    @PostMapping("/verify-change-password")
    public ResponseEntity<Map<String, Object>> verifyChangePassword(@RequestBody ChangePasswordDto dto,
                                                                    HttpServletRequest request) throws Exception {
        return userService.verifyChangePassword(dto, request);
    }

    @PostMapping("/email-change-request")
    public ResponseEntity<Map<String, String>> emailChangeRequest(@RequestBody NewEmailRequestDto newEmailRequest,
                                                                  HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.emailChangeRequest(newEmailRequest.getNewEmail(), request));
    }

    @PostMapping("/verify-email-change")
    public ResponseEntity<Map<String, Object>> verifyEmailChange(@RequestBody EmailChangeRequestDto emailChangeRequest,
                                                                 HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.verifyEmailChange(emailChangeRequest.getNewEmailOtp(), emailChangeRequest.getOldEmailOtp(), emailChangeRequest.getPassword(), request));
    }

    @DeleteMapping("/delete-account")
    public ResponseEntity<Map<String, Object>> deleteAccount(@RequestBody PasswordRequestDto passwordRequest,
                                                             HttpServletRequest request) throws Exception {
        return userService.deleteAccount(passwordRequest.getPassword(), request);
    }

    @PostMapping("/delete-account-method-selection")
    public ResponseEntity<Map<String, String>> deleteAccountMethodSelection(@RequestParam String method,
                                                                            HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.deleteAccountMethodSelection(method, request));
    }

    @DeleteMapping("/verify-delete-account")
    public ResponseEntity<Map<String, String>> verifyDeleteAccount(@RequestBody DeleteAccountRequestDto deleteAccountRequest,
                                                                   HttpServletRequest request) throws Exception {
        return ResponseEntity.ok(userService.verifyDeleteAccount(deleteAccountRequest.getOtpTotp(), deleteAccountRequest.getMethod(), request));
    }

    @PutMapping("/update-details")
    public ResponseEntity<Map<String, Object>> updateDetails(@RequestBody SelfUpdationDto dto,
                                                             HttpServletRequest request) throws Exception {
        return userService.updateDetails(dto, request);
    }
}
