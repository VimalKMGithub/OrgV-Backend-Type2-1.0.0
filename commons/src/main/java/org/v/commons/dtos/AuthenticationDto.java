package org.v.commons.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationDto {
    private String userId;
    private String username;
    private String email;
    private String realEmail;
    private boolean mfaEnabled;
    private String mfaMethods;
    private String authorities;
    private String emailsFromExternalIdentities;
}
