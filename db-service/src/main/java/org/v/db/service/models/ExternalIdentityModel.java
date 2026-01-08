package org.v.db.service.models;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "external_identities",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_provider_user_id",
                        columnNames = {"provider", "provider_user_id"}
                ),
                @UniqueConstraint(
                        name = "uk_user_provider",
                        columnNames = {"user_id", "provider"}
                )
        },
        indexes = {
                @Index(
                        name = "idx_provider_user_id",
                        columnList = "provider, provider_user_id"
                ),
                @Index(
                        name = "idx_user_id",
                        columnList = "user_id"
                ),
                @Index(
                        name = "idx_email",
                        columnList = "email"
                )
        })
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ExternalIdentityModel {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "UUID",
            updatable = false,
            nullable = false,
            unique = true)
    private UUID id;

    @Column(name = "provider",
            nullable = false,
            length = 512)
    private String provider;

    @Column(name = "provider_user_id",
            nullable = false,
            length = 512)
    private String providerUserId;

    @Column(name = "email",
            nullable = false,
            length = 512)
    private String email;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id",
            nullable = false)
    @JsonBackReference
    private UserModel user;

    @Column(name = "created_at",
            updatable = false,
            nullable = false)
    private Instant createdAt;

    @Column(name = "linked_at",
            nullable = false,
            updatable = false)
    private Instant linkedAt;

    @Column(name = "last_used_at",
            nullable = false)
    private Instant lastUsedAt;

    @Column(name = "profile_picture_url",
            length = 2048)
    private String profilePictureUrl;

    @Transient
    @JsonProperty("userId")
    public UUID getUserId() {
        return user != null ? user.getId() : null;
    }

    @JsonProperty("userId")
    public void setUserId(UUID userId) {
        if (userId != null) {
            this.user = new UserModel();
            this.user.setId(userId);
        }
    }

    @PrePersist
    public void recordCreation() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.linkedAt = now;
        this.lastUsedAt = now;
    }
}
