package org.v.db.service.models;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.v.commons.enums.MfaType;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users",
        indexes = {
                @Index(
                        name = "idx_username",
                        columnList = "username",
                        unique = true
                ),
                @Index(
                        name = "idx_email",
                        columnList = "email",
                        unique = true
                ),
                @Index(
                        name = "idx_real_email",
                        columnList = "realEmail",
                        unique = true
                )
        },
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_users_username",
                        columnNames = "username"
                ),
                @UniqueConstraint(
                        name = "uk_users_email",
                        columnNames = "email"
                ),
                @UniqueConstraint(
                        name = "uk_users_real_email",
                        columnNames = "realEmail"
                )
        })
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserModel {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "UUID",
            updatable = false,
            nullable = false,
            unique = true)
    private UUID id;

    @Column(name = "first_name",
            nullable = false,
            length = 50)
    private String firstName;

    @Column(name = "middle_name",
            length = 50)
    private String middleName;

    @Column(name = "last_name",
            length = 50)
    private String lastName;

    @Column(name = "username",
            nullable = false,
            unique = true,
            length = 512)
    private String username;

    @Column(name = "password",
            nullable = false,
            length = 512)
    private String password;

    @Column(name = "email",
            nullable = false,
            unique = true,
            length = 512)
    private String email;

    @Column(name = "real_email",
            nullable = false,
            unique = true,
            length = 512)
    private String realEmail;

    @Builder.Default
    @Column(name = "email_verified",
            nullable = false)
    private boolean emailVerified = false;

    @Builder.Default
    @Column(name = "mfa_enabled",
            nullable = false)
    private boolean mfaEnabled = false;

    @Builder.Default
    @Column(name = "account_locked",
            nullable = false)
    private boolean accountLocked = false;

    @Builder.Default
    @Column(name = "account_enabled",
            nullable = false)
    private boolean accountEnabled = true;

    @Builder.Default
    @Column(name = "account_deleted",
            nullable = false)
    private boolean accountDeleted = false;

    @Column(name = "account_deleted_at")
    private Instant accountDeletedAt;

    @Column(name = "account_deleted_by",
            length = 512)
    private String accountDeletedBy;

    @Column(name = "account_recovered_at")
    private Instant accountRecoveredAt;

    @Column(name = "account_recovered_by",
            length = 512)
    private String accountRecoveredBy;

    @Column(name = "auth_app_secret",
            length = 512)
    private String authAppSecret;

    @ManyToMany(fetch = FetchType.LAZY, cascade = CascadeType.MERGE)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(
                    name = "user_id",
                    referencedColumnName = "id"
            ),
            inverseJoinColumns = @JoinColumn(
                    name = "role_name",
                    referencedColumnName = "role_name"
            )
    )
    private Set<RoleModel> roles;

    @Column(name = "login_at")
    private Instant loginAt;

    @Column(name = "locked_at")
    private Instant lockedAt;

    @Builder.Default
    @Column(name = "failed_login_attempts",
            nullable = false)
    private int failedLoginAttempts = 0;

    @Builder.Default
    @Column(name = "failed_mfa_attempts",
            nullable = false)
    private int failedMfaAttempts = 0;

    @Builder.Default
    @Column(name = "allowed_concurrent_logins",
            nullable = false)
    private int allowedConcurrentLogins = 1;

    @Column(name = "password_changed_at",
            nullable = false)
    private Instant passwordChangedAt;

    @Column(name = "created_at",
            updatable = false,
            nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by",
            nullable = false,
            updatable = false,
            length = 512)
    private String createdBy;

    @Column(name = "updated_by",
            length = 512)
    private String updatedBy;

    @PrePersist
    public void recordCreation() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.passwordChangedAt = now;
    }

    @ElementCollection(targetClass = MfaType.class,
            fetch = FetchType.LAZY)
    @CollectionTable(name = "user_mfa_methods",
            joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "mfa_type",
            nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<MfaType> mfaMethods;

    @Builder.Default
    @Column(name = "oauth2_user",
            nullable = false)
    private boolean oauth2User = false;

    @OneToMany(mappedBy = "user",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY)
    @JsonManagedReference
    private Set<ExternalIdentityModel> externalIdentities;
}
