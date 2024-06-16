package com.gw2auth.oauth2.server.repository.summary;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface SummaryRepository extends BaseRepository<ApplicationSummaryEntity> {

    @Query("""
    SELECT
        (SELECT COUNT(*) FROM accounts) AS accounts,
        (SELECT COUNT(*) FROM gw2_account_api_tokens WHERE last_valid_time = last_valid_check_time) AS api_tokens,
        (SELECT COUNT(*) FROM gw2_account_verifications) AS verified_gw2_accounts,
        (SELECT COUNT(*) FROM application_clients) AS client_registrations,
        (SELECT COUNT(*) FROM application_client_accounts WHERE ARRAY_LENGTH(authorized_scopes, 1) > 0) AS client_authorizations
    """)
    ApplicationSummaryEntity getApplicationSummary();
}
