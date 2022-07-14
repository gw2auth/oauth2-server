package com.gw2auth.oauth2.server.repository.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface ClientAuthorizationTokenRepository extends BaseRepository<ClientAuthorizationTokenEntity>, CustomClientAuthorizationTokenRepository {

    @Override
    default ClientAuthorizationTokenEntity save(ClientAuthorizationTokenEntity entity) {
        return save(entity.clientAuthorizationId(), entity.accountId(), entity.gw2AccountId());
    }

    @Query("""
    INSERT INTO client_authorization_tokens
    (client_authorization_id, account_id, gw2_account_id)
    VALUES
    (:client_authorization_id, :account_id, :gw2_account_id)
    ON CONFLICT DO NOTHING
    RETURNING *
    """)
    ClientAuthorizationTokenEntity save(@Param("client_authorization_id") String clientAuthorizationId,
                                        @Param("account_id") UUID accountId,
                                        @Param("gw2_account_id") UUID gw2AccountId);

    @Query("SELECT * FROM client_authorization_tokens WHERE account_id = :account_id")
    List<ClientAuthorizationTokenEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("""
    SELECT *
    FROM client_authorization_tokens
    WHERE account_id = :account_id AND client_authorization_id = :client_authorization_id
    """)
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientAuthorizationId(@Param("account_id") UUID accountId, @Param("client_authorization_id") String clientAuthorizationId);

    @Query("""
    SELECT *
    FROM client_authorization_tokens
    WHERE account_id = :account_id AND client_authorization_id = ANY(ARRAY[ :client_authorization_ids ]::TEXT[])
    """)
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientAuthorizationIds(@Param("account_id") UUID accountId, @Param("client_authorization_ids") Collection<String> clientAuthorizationIds);

    @Modifying
    @Query("DELETE FROM client_authorization_tokens WHERE account_id = :account_id AND client_authorization_id = :client_authorization_id")
    void deleteAllByAccountIdAndClientAuthorizationId(@Param("account_id") UUID accountId, @Param("client_authorization_id") String clientAuthorizationId);
}
