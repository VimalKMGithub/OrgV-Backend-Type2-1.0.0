package org.v.auth.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDto {
    private String usernameOrEmailOrId;
    private String password;
}
