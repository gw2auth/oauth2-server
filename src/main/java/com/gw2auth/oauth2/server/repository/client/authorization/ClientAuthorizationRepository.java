package com.gw2auth.oauth2.server.repository.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface ClientAuthorizationRepository extends BaseRepository<ClientAuthorizationEntity> {

    @Override
    default ClientAuthorizationEntity save(ClientAuthorizationEntity clientAuthorizationEntity) {
        return save(clientAuthorizationEntity.accountId(), clientAuthorizationEntity.clientRegistrationId(), clientAuthorizationEntity.accountSub(), clientAuthorizationEntity.authorizedScopes());
    }

    @Query("""
    INSERT INTO client_authorizations
    (account_id, client_registration_id, account_sub, authorized_scopes)
    VALUES
    (:account_id, :client_registration_id, :account_sub, ARRAY[ :authorized_scopes ]::VARCHAR[])
    ON CONFLICT (account_id, client_registration_id) DO UPDATE SET
    account_sub = EXCLUDED.account_sub,
    authorized_scopes = EXCLUDED.authorized_scopes
    RETURNING *
    """)
    ClientAuthorizationEntity save(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId, @Param("account_sub") UUID accountSub, @Param("authorized_scopes") Set<String> authorizedScopes);

    @Query("SELECT * FROM client_authorizations WHERE account_id = :account_id")
    List<ClientAuthorizationEntity> findAllByAccountId(@Param("account_id") long accountId);

    @Query("SELECT auth.* FROM client_authorizations auth INNER JOIN client_registrations reg ON auth.client_registration_id = reg.id WHERE auth.account_id = :account_id AND reg.client_id = :client_id")
    Optional<ClientAuthorizationEntity> findByAccountIdAndClientId(@Param("account_id") long accountId, @Param("client_id") String clientId);

    @Query("SELECT * FROM client_authorizations WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    Optional<ClientAuthorizationEntity> findByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);
}
