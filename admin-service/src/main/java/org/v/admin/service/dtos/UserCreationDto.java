package org.v.admin.service.dtos;

import lombok.Getter;
import lombok.Setter;
import org.v.commons.dtos.RegistrationDto;

import java.util.Set;

@Getter
@Setter
public class UserCreationDto extends RegistrationDto {
    private Set<String> roles;
    private int allowedConcurrentLogins = 1;
    private boolean emailVerified;
    private boolean accountLocked;
    private boolean accountEnabled;
    private boolean accountDeleted;
}
