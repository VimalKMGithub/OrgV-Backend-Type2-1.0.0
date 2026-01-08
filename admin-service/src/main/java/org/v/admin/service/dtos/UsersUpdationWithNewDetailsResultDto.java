package org.v.admin.service.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.v.commons.models.UserModel;

import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UsersUpdationWithNewDetailsResultDto {
    private Set<UserModel> updatedUsers;
    private Set<UUID> idsOfUsersWeHaveToRemoveTokens;
}
