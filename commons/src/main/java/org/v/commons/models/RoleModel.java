package org.v.commons.models;

import lombok.*;

import java.time.Instant;
import java.util.Set;

@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class RoleModel {
    @EqualsAndHashCode.Include
    private String roleName;
    private String description;
    @Builder.Default
    private boolean systemRole = false;
    private Set<PermissionModel> permissions;
    private Instant createdAt;
    private Instant updatedAt;
    private String createdBy;
    private String updatedBy;

    public void recordUpdation(String updater) {
        this.updatedAt = Instant.now();
        this.updatedBy = updater;
    }
}
