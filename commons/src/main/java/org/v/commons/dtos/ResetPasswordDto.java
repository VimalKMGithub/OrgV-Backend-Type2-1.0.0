package org.v.commons.dtos;

import lombok.Getter;
import lombok.Setter;

import static org.v.commons.enums.MfaType.DEFAULT_MFA;

@Getter
@Setter
public class ResetPasswordDto {
    private String usernameOrEmailOrId;
    private String otpTotp;
    private String method = DEFAULT_MFA;
    private String newPassword;
    private String confirmNewPassword;
}
