package org.v.commons.models;

import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ExternalIdentityModel {
    private UUID id;
    private String provider;
    private String providerUserId;
    private String email;
    private Instant createdAt;
    private Instant linkedAt;
    private Instant lastUsedAt;
    private String profilePictureUrl;
    private UUID userId;
}
