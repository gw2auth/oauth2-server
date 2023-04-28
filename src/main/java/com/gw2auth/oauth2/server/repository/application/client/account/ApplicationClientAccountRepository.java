package com.gw2auth.oauth2.server.repository.application.client.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface ApplicationClientAccountRepository extends BaseRepository<ApplicationClientAccountEntity> {

    @Override
    default ApplicationClientAccountEntity save(ApplicationClientAccountEntity entity) {
        return save(
                entity.applicationClientId(),
                entity.accountId(),
                entity.applicationId(),
                entity.approvalStatus(),
                entity.approvalRequestMessage(),
                entity.authorizedScopes()
        );
    }

    @Query("""
    INSERT INTO application_client_accounts
    (application_client_id, account_id, application_id, approval_status, approval_request_message, authorized_scopes)
    VALUES
    (:application_client_id, :account_id, :application_id, :approval_status, :approval_request_message, ARRAY[ :authorized_scopes ]::TEXT[])
    ON CONFLICT (application_client_id, account_id) DO UPDATE SET
    approval_status = EXCLUDED.approval_status,
    approval_request_message = EXCLUDED.approval_request_message,
    authorized_scopes = EXCLUDED.authorized_scopes
    RETURNING *
    """)
    ApplicationClientAccountEntity save(@Param("application_client_id") UUID applicationClientId,
                                        @Param("account_id") UUID accountId,
                                        @Param("application_id") UUID applicationId,
                                        @Param("approval_status") String approvalStatus,
                                        @Param("approval_request_message") String approvalRequestMessage,
                                        @Param("authorized_scopes") Set<String> authorizedScopes);

    @Query("""
    SELECT *
    FROM application_client_accounts
    WHERE account_id = :account_id
    """)
    List<ApplicationClientAccountEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("""
    SELECT *
    FROM application_client_accounts
    WHERE application_client_id = :application_client_id
    AND account_id = :account_id
    """)
    Optional<ApplicationClientAccountEntity> findByApplicationClientIdAndAccountId(@Param("application_client_id") UUID applicationClientId,
                                                                                   @Param("account_id") UUID accountId);

    @Modifying
    @Query("""
    UPDATE application_client_accounts
    SET authorized_scopes = ARRAY[ :authorized_scopes ]::TEXT[]
    WHERE application_client_id = :application_client_id
    AND account_id = :account_id
    """)
    void updateAuthorizedScopesByApplicationClientIdAndAccountId(@Param("application_client_id") UUID applicationClientId,
                                                                 @Param("account_id") UUID accountId,
                                                                 @Param("authorized_scopes") Set<String> authorizedScopes);

    @Modifying
    @Query("""
    DELETE FROM application_client_accounts
    WHERE application_client_id = :application_client_id
    AND account_id = :account_id
    """)
    void deleteByApplicationClientIdAndAccountId(@Param("application_client_id") UUID applicationClientId,
                                                 @Param("account_id") UUID accountId);
}
