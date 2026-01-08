package org.v.db.service.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.v.db.service.models.ExternalIdentityModel;

import java.util.UUID;

@Repository
public interface ExternalIdentityRepo extends JpaRepository<ExternalIdentityModel, UUID> {
    ExternalIdentityModel findByProviderAndProviderUserId(String provider, String providerUserId);

    boolean existsByEmail(String email);
}
