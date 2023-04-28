package com.gw2auth.oauth2.server.repository.application;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApplicationRepository extends BaseRepository<ApplicationEntity> {

    @Override
    default ApplicationEntity save(ApplicationEntity entity) {
        return save(
                entity.id(),
                entity.accountId(),
                entity.creationTime(),
                entity.displayName()
        );
    }

    @Query("""
    INSERT INTO applications
    (id, account_id, creation_time, display_name)
    VALUES
    (:id, :account_id, :creation_time, :display_name)
    RETURNING *
    """)
    ApplicationEntity save(@Param("id") UUID id,
                           @Param("account_id") UUID accountId,
                           @Param("creation_time") Instant creationTime,
                           @Param("display_name") String displayName);

    @Query("""
    SELECT *
    FROM applications
    WHERE id = :id
    """)
    Optional<ApplicationEntity> findById(@Param("id") UUID id);

    @Query("""
    SELECT *
    FROM applications
    WHERE id = :id
    AND account_id = :account_id
    """)
    Optional<ApplicationEntity> findByIdAndAccountId(@Param("id") UUID id, @Param("account_id") UUID accountId);

    @Modifying
    @Query("""
    DELETE FROM applications
    WHERE id = :id
    AND account_id = :account_id
    """)
    boolean deleteByIdAndAccountId(@Param("id") UUID id, @Param("account_id") UUID accountId);
}
