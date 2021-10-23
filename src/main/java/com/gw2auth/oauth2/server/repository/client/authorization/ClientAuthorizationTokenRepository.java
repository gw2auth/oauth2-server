package com.gw2auth.oauth2.server.repository.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

@Repository
public interface ClientAuthorizationTokenRepository extends BaseRepository<ClientAuthorizationTokenEntity> {

    @Override
    default ClientAuthorizationTokenEntity save(ClientAuthorizationTokenEntity clientAuthorizationTokenEntity) {
        return save(clientAuthorizationTokenEntity.accountId(), clientAuthorizationTokenEntity.clientRegistrationId(), clientAuthorizationTokenEntity.gw2AccountId(), clientAuthorizationTokenEntity.gw2ApiSubtoken(), clientAuthorizationTokenEntity.expirationTime());
    }

    @Query("""
    INSERT INTO client_authorization_tokens
    (account_id, client_registration_id, gw2_account_id, gw2_api_subtoken, expiration_time)
    VALUES
    (:account_id, :client_registration_id, :gw2_account_id, :gw2_api_subtoken, :expiration_time)
    ON CONFLICT (account_id, client_registration_id, gw2_account_id) DO UPDATE SET
    gw2_api_subtoken = EXCLUDED.gw2_api_subtoken,
    expiration_time = EXCLUDED.expiration_time
    RETURNING *
    """)
    ClientAuthorizationTokenEntity save(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId, @Param("gw2_account_id") String gw2AccountId, @Param("gw2_api_subtoken") String gw2ApiSubtoken, @Param("expiration_time") Instant expirationTime);

    @Query("SELECT * FROM client_authorization_tokens WHERE account_id = :account_id")
    List<ClientAuthorizationTokenEntity> findAllByAccountId(@Param("account_id") long accountId);

    @Query("SELECT * FROM client_authorization_tokens WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);

    @Query("SELECT * FROM client_authorization_tokens WHERE account_id = :account_id AND client_registration_id = ANY(ARRAY[ :client_registration_ids ]::BIGINT[])")
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientRegistrationIds(@Param("account_id") long accountId, @Param("client_registration_ids") Collection<Long> clientRegistrationIds);

    @Modifying
    @Query("DELETE FROM client_authorization_tokens WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    int deleteAllByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);
}
