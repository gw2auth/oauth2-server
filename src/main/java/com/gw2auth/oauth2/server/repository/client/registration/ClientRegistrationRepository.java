package com.gw2auth.oauth2.server.repository.client.registration;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

@Repository("jdbcClientRegistrationRepository")
public interface ClientRegistrationRepository extends BaseRepository<ClientRegistrationEntity> {

    @Override
    default ClientRegistrationEntity save(ClientRegistrationEntity entity) {
        return save(entity.id(), entity.accountId(), entity.creationTime(), entity.displayName(), entity.clientSecret(), entity.authorizationGrantTypes(), entity.redirectUris());
    }

    @Query("""
    INSERT INTO client_registrations
    (id, account_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris)
    VALUES
    (:id, :account_id, :creation_time, :display_name, :client_secret, ARRAY[ :authorization_grant_types ]::TEXT[], ARRAY[ :redirect_uris ]::TEXT[])
    ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    client_secret = EXCLUDED.client_secret,
    authorization_grant_types = EXCLUDED.authorization_grant_types,
    redirect_uris = EXCLUDED.redirect_uris
    RETURNING *
    """)
    ClientRegistrationEntity save(@Param("id") UUID id,
                                  @Param("account_id") UUID accountId,
                                  @Param("creation_time") Instant creationTime,
                                  @Param("display_name") String displayName,
                                  @Param("client_secret") String clientSecret,
                                  @Param("authorization_grant_types") Set<String> authorizationGrantTypes,
                                  @Param("redirect_uris") Set<String> redirectUris);

    @Query("SELECT * FROM client_registrations WHERE account_id = :account_id")
    List<ClientRegistrationEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("SELECT * FROM client_registrations WHERE account_id = :account_id AND id = :id")
    Optional<ClientRegistrationEntity> findByAccountIdAndId(@Param("account_id") UUID accountId, @Param("id") UUID id);

    @Query("SELECT * FROM client_registrations WHERE id = :id")
    Optional<ClientRegistrationEntity> findById(@Param("id") UUID id);

    @Query("SELECT * FROM client_registrations WHERE id = ANY(ARRAY[ :ids ]::UUID[])")
    List<ClientRegistrationEntity> findAllByIds(@Param("ids") Collection<UUID> ids);

    @Modifying
    @Query("DELETE FROM client_registrations WHERE account_id = :account_id AND id = :id")
    boolean deleteByAccountIdAndId(@Param("account_id") UUID accountId, @Param("id") UUID id);
}
