package org.v.db.service.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.v.db.service.models.UserModel;

import java.util.Collection;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<UserModel, UUID> {
    UserModel findByUsername(String username);

    UserModel findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByRealEmail(String realEmail);

    Collection<UserModel> findByUsernameIn(Collection<String> usernames);

    Collection<UserModel> findByEmailIn(Collection<String> emails);

    UserModel findByRealEmail(String realEmail);
}
