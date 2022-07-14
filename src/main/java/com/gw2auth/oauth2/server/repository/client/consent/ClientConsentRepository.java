package com.gw2auth.oauth2.server.repository.client.consent;

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
public interface ClientConsentRepository extends BaseRepository<ClientConsentEntity> {

    @Override
    default ClientConsentEntity save(ClientConsentEntity clientConsentEntity) {
        return save(clientConsentEntity.accountId(), clientConsentEntity.clientRegistrationId(), clientConsentEntity.accountSub(), clientConsentEntity.authorizedScopes());
    }

    @Query("""
    INSERT INTO client_consents
    (account_id, client_registration_id, account_sub, authorized_scopes)
    VALUES
    (:account_id, :client_registration_id, :account_sub, ARRAY[ :authorized_scopes ]::TEXT[])
    ON CONFLICT (account_id, client_registration_id) DO UPDATE SET
    account_sub = EXCLUDED.account_sub,
    authorized_scopes = EXCLUDED.authorized_scopes
    RETURNING *
    """)
    ClientConsentEntity save(@Param("account_id") UUID accountId, @Param("client_registration_id") UUID clientRegistrationId, @Param("account_sub") UUID accountSub, @Param("authorized_scopes") Set<String> authorizedScopes);

    @Query("SELECT * FROM client_consents WHERE account_id = :account_id")
    List<ClientConsentEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("SELECT * FROM client_consents WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    Optional<ClientConsentEntity> findByAccountIdAndClientRegistrationId(@Param("account_id") UUID accountId, @Param("client_registration_id") UUID clientRegistrationId);

    @Modifying
    @Query("DELETE FROM client_consents WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    void deleteByAccountIdAndClientRegistrationId(@Param("account_id") UUID accountId, @Param("client_registration_id") UUID clientRegistrationId);
}
