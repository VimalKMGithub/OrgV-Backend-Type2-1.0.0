--liquibase formatted sql

--changeset vimal:001
-- ===========================================================
-- TABLE: permissions
-- ===========================================================
CREATE TABLE permissions (
    permission_name VARCHAR(100) PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    created_by VARCHAR(512) NOT NULL
);
CREATE INDEX idx_permissions_created_by ON permissions (created_by);
--rollback DROP TABLE permissions;


--changeset vimal:002
-- ===========================================================
-- TABLE: roles and role_permissions
-- ===========================================================
CREATE TABLE roles (
    role_name VARCHAR(100) PRIMARY KEY,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP,
    created_by VARCHAR(512) NOT NULL,
    updated_by VARCHAR(512)
);

CREATE TABLE role_permissions (
    role_name VARCHAR(100) NOT NULL,
    permission_name VARCHAR(100) NOT NULL,
    CONSTRAINT pk_role_permissions PRIMARY KEY (role_name, permission_name),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_name) REFERENCES roles (role_name),
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_name) REFERENCES permissions (permission_name)
);

CREATE INDEX idx_role_permissions_role_name ON role_permissions (role_name);
CREATE INDEX idx_role_permissions_permission_name ON role_permissions (permission_name);
--rollback DROP TABLE role_permissions; DROP TABLE roles;


--changeset vimal:003
-- ===========================================================
-- TABLE: users
-- ===========================================================
CREATE TABLE users (
    id UUID PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    middle_name VARCHAR(50),
    last_name VARCHAR(50),
    username VARCHAR(512) NOT NULL UNIQUE,
    password VARCHAR(512) NOT NULL,
    email VARCHAR(512) NOT NULL UNIQUE,
    real_email VARCHAR(512) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    account_locked BOOLEAN NOT NULL DEFAULT FALSE,
    account_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    account_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    account_deleted_at TIMESTAMP,
    account_deleted_by VARCHAR(512),
    account_recovered_at TIMESTAMP,
    account_recovered_by VARCHAR(512),
    auth_app_secret VARCHAR(512),
    login_at TIMESTAMP,
    locked_at TIMESTAMP,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    failed_mfa_attempts INT NOT NULL DEFAULT 0,
    allowed_concurrent_logins INT NOT NULL DEFAULT 1,
    password_changed_at TIMESTAMP NOT NULL DEFAULT now(),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP,
    created_by VARCHAR(512) NOT NULL,
    updated_by VARCHAR(512),
    oauth2_user BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_real_email ON users (real_email);
CREATE INDEX idx_users_created_by ON users (created_by);
--rollback DROP TABLE users;


--changeset vimal:004
-- ===========================================================
-- TABLE: user_roles & user_mfa_methods
-- ===========================================================
CREATE TABLE user_roles (
    user_id UUID NOT NULL,
    role_name VARCHAR(100) NOT NULL,
    CONSTRAINT pk_user_roles PRIMARY KEY (user_id, role_name),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_name) REFERENCES roles (role_name)
);

CREATE INDEX idx_user_roles_user_id ON user_roles (user_id);
CREATE INDEX idx_user_roles_role_name ON user_roles (role_name);

CREATE TABLE user_mfa_methods (
    user_id UUID NOT NULL,
    mfa_type VARCHAR(50) NOT NULL,
    CONSTRAINT pk_user_mfa PRIMARY KEY (user_id, mfa_type),
    CONSTRAINT fk_user_mfa_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_user_mfa_user_id ON user_mfa_methods (user_id);
CREATE INDEX idx_user_mfa_type ON user_mfa_methods (mfa_type);
--rollback DROP TABLE user_roles; DROP TABLE user_mfa_methods;


--changeset vimal:005
-- ===========================================================
-- TABLE: external_identities
-- ===========================================================
CREATE TABLE external_identities (
    id UUID PRIMARY KEY,
    provider VARCHAR(512) NOT NULL,
    provider_user_id VARCHAR(512) NOT NULL,
    email VARCHAR(512) NOT NULL,
    user_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    linked_at TIMESTAMP NOT NULL DEFAULT now(),
    last_used_at TIMESTAMP NOT NULL DEFAULT now(),
    profile_picture_url VARCHAR(2048) NULL,

    CONSTRAINT fk_external_identity_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON DELETE CASCADE,

    CONSTRAINT uk_provider_user_id
        UNIQUE (provider, provider_user_id),

    CONSTRAINT uk_user_provider
        UNIQUE (user_id, provider)
);

CREATE INDEX idx_external_provider_user_id
    ON external_identities (provider, provider_user_id);

CREATE INDEX idx_external_user_id
    ON external_identities (user_id);

CREATE INDEX idx_external_email
    ON external_identities (email);

CREATE INDEX idx_external_last_used_at
    ON external_identities (last_used_at);
--rollback DROP TABLE external_identities;
