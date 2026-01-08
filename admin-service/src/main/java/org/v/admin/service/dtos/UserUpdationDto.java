package org.v.admin.service.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserUpdationDto extends UserCreationDto {
    private String oldUsername;
}
