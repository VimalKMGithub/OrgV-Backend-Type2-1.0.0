package org.v.auth.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ToggleMfaRequestDto {
    private String type;
    private String toggle;
    private String otpTotp;
}
