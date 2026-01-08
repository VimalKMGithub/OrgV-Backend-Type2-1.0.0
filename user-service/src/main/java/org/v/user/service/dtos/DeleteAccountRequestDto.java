package org.v.user.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteAccountRequestDto {
    private String otpTotp;
    private String method;
}
