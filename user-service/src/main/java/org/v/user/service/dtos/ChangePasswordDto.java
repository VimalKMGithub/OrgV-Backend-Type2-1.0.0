package org.v.user.service.dtos;

import lombok.Getter;
import lombok.Setter;
import org.v.commons.dtos.ResetPasswordDto;

@Getter
@Setter
public class ChangePasswordDto extends ResetPasswordDto {
    private String oldPassword;
}
