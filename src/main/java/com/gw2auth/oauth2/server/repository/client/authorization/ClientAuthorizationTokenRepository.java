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
public interface ClientAuthorizationTokenRepository extends BaseRepository<ClientAuthorizationTokenEntity> {

    @Override
    default ClientAuthorizationTokenEntity save(ClientAuthorizationTokenEntity entity) {
        return save(entity.accountId(), entity.clientAuthorizationId(), entity.gw2AccountId());
    }

    @Query("""
    INSERT INTO client_authorization_tokens
    (account_id, client_authorization_id, gw2_account_id)
    VALUES
    (:account_id, :client_authorization_id, :gw2_account_id)
    ON CONFLICT DO NOTHING
    RETURNING *
    """)
    ClientAuthorizationTokenEntity save(@Param("account_id") long accountId,
                                        @Param("client_authorization_id") String clientAuthorizationId,
                                        @Param("gw2_account_id") UUID gw2AccountId);

    @Query("SELECT * FROM client_authorization_tokens WHERE account_id = :account_id")
    List<ClientAuthorizationTokenEntity> findAllByAccountId(@Param("account_id") long accountId);

    @Query("""
    SELECT *
    FROM client_authorization_tokens
    WHERE account_id = :account_id AND client_authorization_id = :client_authorization_id
    """)
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientAuthorizationId(@Param("account_id") long accountId, @Param("client_authorization_id") String clientAuthorizationId);

    @Query("""
    SELECT *
    FROM client_authorization_tokens
    WHERE account_id = :account_id AND client_authorization_id = ANY(ARRAY[ :client_authorization_ids ]::TEXT[])
    """)
    List<ClientAuthorizationTokenEntity> findAllByAccountIdAndClientAuthorizationIds(@Param("account_id") long accountId, @Param("client_authorization_ids") Collection<String> clientAuthorizationIds);

    @Modifying
    @Query("DELETE FROM client_authorization_tokens WHERE account_id = :account_id AND client_authorization_id = :client_authorization_id")
    void deleteAllByAccountIdAndClientAuthorizationId(@Param("account_id") long accountId, @Param("client_authorization_id") String clientAuthorizationId);

    @Modifying
    //@Query("DELETE FROM client_authorization_tokens WHERE account_id = :account_id AND client_authorization_id = :client_authorization_id")
    @Query("""
    DELETE FROM client_authorization_tokens auth_tk
    WHERE auth_tk.account_id = :account_id
    AND auth_tk.client_authorization_id = (
        SELECT id
        FROM client_authorizations auth
        WHERE auth.account_id = auth_tk.account_id
        AND auth.client_registration_id = :client_registration_id
        LIMIT 1
    )
    """)
    void deleteAllByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);
}
