package com.gw2auth.oauth2.server.repository.summary;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
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

    @Query("""
    WITH auth_past_Xd AS (
        SELECT
            COUNT(*) FILTER ( WHERE (creation_time + INTERVAL '1' DAY) >= :now ) AS past_1d,
            COUNT(*) FILTER ( WHERE (creation_time + INTERVAL '3' DAY) >= :now ) AS past_3d,
            COUNT(*) FILTER ( WHERE (creation_time + INTERVAL '7' DAY) >= :now ) AS past_7d,
            COUNT(*) AS past_30d
        FROM client_authorizations
        WHERE client_registration_id = :client_id
        AND access_token_value IS NOT NULL
        AND (creation_time + INTERVAL '30' DAY) >= :now
    )
    SELECT
        (
            SELECT COUNT(*)
            FROM client_consents
            WHERE client_registration_id = :client_id
        ) AS accounts,
        
        (
            SELECT COUNT(*)
            FROM (
                SELECT DISTINCT auth_tk.gw2_account_id
                FROM client_authorization_tokens auth_tk
                INNER JOIN client_authorizations auth
                ON auth_tk.client_authorization_id = auth.id
                WHERE auth.client_registration_id = :client_id
            ) AS sub
        ) AS gw2_accounts,
        
        (
            SELECT past_1d
            FROM auth_past_Xd
        ) AS authorizations_past_1d,
        
        (
            SELECT past_3d
            FROM auth_past_Xd
        ) AS authorizations_past_3d,
        
        (
            SELECT past_7d
            FROM auth_past_Xd
        ) AS authorizations_past_7d,
        
        (
            SELECT past_30d
            FROM auth_past_Xd
        ) AS authorizations_past_30d
    """)
    ClientSummaryEntity getClientSummary(@Param("client_id") UUID clientId, @Param("now") Instant now);
}
