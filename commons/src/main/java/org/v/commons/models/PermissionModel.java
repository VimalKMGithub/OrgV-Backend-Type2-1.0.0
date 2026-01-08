package org.v.commons.models;

import lombok.*;

import java.time.Instant;

@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class PermissionModel {
    @EqualsAndHashCode.Include
    private String permissionName;
    private Instant createdAt;
    private String createdBy;
}
