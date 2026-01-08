package org.v.auth.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginMfaRequestDto {
    private String type;
    private String stateToken;
    private String otpTotp;
}
