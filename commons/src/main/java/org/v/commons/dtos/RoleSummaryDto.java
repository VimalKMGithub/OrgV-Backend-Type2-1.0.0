package org.v.commons.dtos;

import lombok.Getter;
import lombok.Setter;
import org.v.commons.models.PermissionModel;

import java.time.Instant;
import java.util.Set;

@Getter
@Setter
public class RoleSummaryDto {
    private String roleName;
    private String description;
    private String createdBy;
    private String updatedBy;
    private Set<PermissionModel> permissions;
    private Instant createdAt;
    private Instant updatedAt;
    private boolean systemRole;
}
