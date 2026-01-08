package org.v.user.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EmailChangeRequestDto {
    private String newEmailOtp;
    private String oldEmailOtp;
    private String password;
}
