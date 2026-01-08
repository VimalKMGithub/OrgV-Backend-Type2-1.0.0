package org.v.admin.service.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.v.commons.models.RoleModel;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RolesUpdationWithNewDetailsResultDto {
    private Set<RoleModel> updatedRoles;
    private Set<String> roleNamesOfRolesWeHaveToRemoveFromUsers;
}
