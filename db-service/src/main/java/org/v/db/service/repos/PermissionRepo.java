package org.v.db.service.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.v.db.service.models.PermissionModel;

@Repository
public interface PermissionRepo extends JpaRepository<PermissionModel, String> {
}
