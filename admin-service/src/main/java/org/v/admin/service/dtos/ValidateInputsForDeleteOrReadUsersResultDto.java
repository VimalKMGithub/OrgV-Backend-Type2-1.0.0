package org.v.admin.service.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ValidateInputsForDeleteOrReadUsersResultDto {
    private Set<String> invalidInputs;
    private Set<String> usernames;
    private Set<String> emails;
    private Set<UUID> ids;
    private Set<String> ownUserInInputs;
}
