package com.gw2auth.oauth2.server.repository.application.client;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

@Repository
public interface ApplicationClientRepository extends BaseRepository<ApplicationClientEntity> {

    @Override
    default ApplicationClientEntity save(ApplicationClientEntity entity) {
        return save(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                entity.clientSecret(),
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval()
        );
    }

    @Query("""
    INSERT INTO application_clients
    (id, application_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris, requires_approval)
    VALUES
    (:id, :application_id, :creation_time, :display_name, :client_secret, ARRAY[ :authorization_grant_types ]::TEXT[], ARRAY[ :redirect_uris ]::TEXT[], :requires_approval)
    ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    client_secret = EXCLUDED.client_secret,
    authorization_grant_types = EXCLUDED.authorization_grant_types,
    redirect_uris = EXCLUDED.redirect_uris,
    requires_approval = EXCLUDED.requires_approval
    RETURNING *
    """)
    ApplicationClientEntity save(@Param("id") UUID id,
                                 @Param("application_id") UUID applicationId,
                                 @Param("creation_time") Instant creationTime,
                                 @Param("display_name") String displayName,
                                 @Param("client_secret") String clientSecret,
                                 @Param("authorization_grant_types") Collection<String> authorizationGrantTypes,
                                 @Param("redirect_uris") Collection<String> redirectUris,
                                 @Param("requires_approval") boolean requiresApproval);

    @Query("""
    SELECT c.*
    FROM application_clients c
    INNER JOIN applications app
    ON c.application_id = app.id
    WHERE app.account_id = :account_id
    """)
    List<ApplicationClientEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("""
    SELECT *
    FROM application_clients
    WHERE id = ANY( ARRAY[ :ids ]::UUID[] )
    """)
    List<ApplicationClientEntity> findAllByIds(@Param("ids") Collection<UUID> ids);

    @Query("""
    SELECT *
    FROM application_clients
    WHERE id = :id
    """)
    Optional<ApplicationClientEntity> findById(@Param("id") UUID id);

    @Query("""
    SELECT app_client.*
    FROM application_clients app_client
    INNER JOIN applications app
    ON app_client.application_id = app.id
    WHERE app_client.id = :id
    AND app.account_id = :account_id
    """)
    Optional<ApplicationClientEntity> findByIdAndAccountId(@Param("id") UUID id, @Param("account_id") UUID accountId);

    @Modifying
    @Query("""
    DELETE FROM application_clients app_client
    WHERE app_client.id = :id
    AND EXISTS(
        SELECT TRUE
        FROM applications app
        WHERE app.id = app_client.application_id
        AND app.account_id = :account_id
    )
    """)
    boolean deleteByIdAndAccountId(@Param("id") UUID id, @Param("account_id") UUID accountId);
}
