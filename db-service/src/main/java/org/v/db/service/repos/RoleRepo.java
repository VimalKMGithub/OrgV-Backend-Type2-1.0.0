package org.v.db.service.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.v.db.service.models.RoleModel;

import java.util.Collection;
import java.util.UUID;

@Repository
public interface RoleRepo extends JpaRepository<RoleModel, String> {
    @Modifying
    @Transactional
    @Query(value = "DELETE FROM user_roles" +
            " WHERE role_name IN (:roleNames)",
            nativeQuery = true)
    void deleteUserRolesByRoleNames(Collection<String> roleNames);

    @Query(value = "SELECT DISTINCT user_id" +
            " FROM user_roles" +
            " WHERE role_name IN (:roleNames)",
            nativeQuery = true)
    Collection<UUID> getUserIdsByRoleNames(Collection<String> roleNames);
}
