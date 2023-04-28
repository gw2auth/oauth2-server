package com.gw2auth.oauth2.server.repository.application.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ApplicationAccountSubRepository extends BaseRepository<ApplicationAccountSubEntity> {

    @Override
    default ApplicationAccountSubEntity save(ApplicationAccountSubEntity entity) {
        throw new UnsupportedOperationException();
    }

    @Query("""
    INSERT INTO application_account_subs
    (application_id, account_id, account_sub)
    VALUES
    (:application_id, :account_id, :account_sub)
    ON CONFLICT (application_id, account_id) DO UPDATE SET
    account_sub = application_account_subs.account_sub
    RETURNING *
    """)
    ApplicationAccountSubEntity findOrCreate(@Param("application_id") UUID applicationId,
                                             @Param("account_id") UUID accountId,
                                             @Param("account_sub") UUID accountSub);
}
