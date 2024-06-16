package com.gw2auth.oauth2.server.repository.application.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ApplicationClientAuthorizationTokenRepository extends BaseRepository<ApplicationClientAuthorizationTokenEntity>, CustomApplicationClientAuthorizationTokenRepository {

    @Override
    default ApplicationClientAuthorizationTokenEntity save(ApplicationClientAuthorizationTokenEntity entity) {
        return save(entity.applicationClientAuthorizationId(), entity.accountId(), entity.gw2AccountId());
    }

    @Query("""
    INSERT INTO application_client_authorization_gw2_accounts
    (application_client_authorization_id, account_id, gw2_account_id)
    VALUES
    (:application_client_authorization_id, :account_id, :gw2_account_id)
    ON CONFLICT (application_client_authorization_id, gw2_account_id) DO UPDATE SET
    account_id = application_client_authorization_gw2_accounts.account_id
    RETURNING *
    """)
    ApplicationClientAuthorizationTokenEntity save(@Param("application_client_authorization_id") String applicationClientAuthorizationId,
                                                   @Param("account_id") UUID accountId,
                                                   @Param("gw2_account_id") UUID gw2AccountId);

    @Query("""
    SELECT *
    FROM application_client_authorization_gw2_accounts
    WHERE application_client_authorization_id = :application_client_authorization_id
    AND account_id = :account_id
    """)
    List<ApplicationClientAuthorizationTokenEntity> findAllByApplicationClientAuthorizationIdAndAccountId(@Param("application_client_authorization_id") String applicationClientAuthorizationId, @Param("account_id") UUID accountId);

    @Modifying
    @Query("DELETE FROM application_client_authorization_gw2_accounts WHERE account_id = :account_id AND application_client_authorization_id = :application_client_authorization_id")
    void deleteAllByAccountIdAndApplicationClientAuthorizationId(@Param("account_id") UUID accountId, @Param("application_client_authorization_id") String applicationClientAuthorizationId);
}
