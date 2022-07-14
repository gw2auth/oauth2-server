package com.gw2auth.oauth2.server.repository.summary;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface SummaryRepository extends BaseRepository<ApplicationSummaryEntity> {

    @Query("""
    SELECT
        (SELECT COUNT(*) FROM accounts) AS accounts,
        (SELECT COUNT(*) FROM gw2_api_tokens) AS api_tokens,
        (SELECT COUNT(*) FROM gw2_account_verifications) AS verified_gw2_accounts,
        (SELECT COUNT(*) FROM client_registrations) AS client_registrations,
        (SELECT COUNT(*) FROM client_consents WHERE ARRAY_LENGTH(authorized_scopes, 1) > 0) AS client_authorizations
    """)
    ApplicationSummaryEntity getApplicationSummary();

    @Query("""
    SELECT
        (SELECT COUNT(*) FROM gw2_api_tokens WHERE account_id = :account_id) AS api_tokens,
        (SELECT COUNT(*) FROM gw2_account_verifications WHERE account_id = :account_id) AS verified_gw2_accounts,
        (SELECT COUNT(*) FROM client_registrations WHERE account_id = :account_id) AS client_registrations,
        (SELECT COUNT(*) FROM client_consents WHERE account_id = :account_id AND ARRAY_LENGTH(authorized_scopes, 1) > 0) AS client_authorizations,
        (SELECT COUNT(*) FROM account_federations WHERE account_id = :account_id) AS account_federations
    """)
    AccountSummaryEntity getAccountSummary(@Param("account_id") UUID accountId);
}
