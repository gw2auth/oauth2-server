package com.gw2auth.oauth2.server.repository.application.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApplicationAccountRepository extends BaseRepository<ApplicationAccountEntity> {

    @Override
    default ApplicationAccountEntity save(ApplicationAccountEntity entity) {
        throw new UnsupportedOperationException();
    }

    @Query("""
    INSERT INTO application_accounts
    (application_id, account_id, creation_time)
    VALUES
    (:application_id, :account_id, :creation_time)
    ON CONFLICT (application_id, account_id) DO UPDATE SET
    creation_time = application_accounts.creation_time
    RETURNING *
    """)
    ApplicationAccountEntity findOrCreate(@Param("application_id") UUID applicationId,
                                          @Param("account_id") UUID accountId,
                                          @Param("creation_time") Instant creationTime);

    @Query("""
    SELECT acc.*, acc_sub.account_sub
    FROM application_accounts acc
    INNER JOIN application_account_subs acc_sub
    ON acc.application_id = acc_sub.application_id AND acc.account_id = acc_sub.account_id
    WHERE acc.application_id = :application_id
    AND acc.account_id = :account_id
    """)
    Optional<ApplicationAccountWithSubEntity> findWithSubByApplicationIdAndAccountId(@Param("application_id") UUID applicationId,
                                                                                     @Param("account_id") UUID accountId);
}
