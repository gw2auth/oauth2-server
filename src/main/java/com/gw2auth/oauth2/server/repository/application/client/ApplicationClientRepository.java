package com.gw2auth.oauth2.server.repository.application.client;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.jspecify.annotations.Nullable;
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
                entity.requiresApproval(),
                entity.apiVersion(),
                entity.type()
        );
    }

    @Query("""
    INSERT INTO application_clients
    (id, application_id, creation_time, display_name, client_secret, authorization_grant_types, redirect_uris, requires_approval, api_version, type)
    VALUES
    (:id, :application_id, :creation_time, :display_name, :client_secret, ARRAY[ :authorization_grant_types ]::TEXT[], ARRAY[ :redirect_uris ]::TEXT[], :requires_approval, :api_version, :type)
    ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    client_secret = EXCLUDED.client_secret,
    authorization_grant_types = EXCLUDED.authorization_grant_types,
    redirect_uris = EXCLUDED.redirect_uris,
    requires_approval = EXCLUDED.requires_approval,
    api_version = EXCLUDED.api_version,
    type = EXCLUDED.type
    RETURNING *
    """)
    ApplicationClientEntity save(@Param("id") UUID id,
                                 @Param("application_id") UUID applicationId,
                                 @Param("creation_time") Instant creationTime,
                                 @Param("display_name") String displayName,
                                 @Param("client_secret") @Nullable String clientSecret,
                                 @Param("authorization_grant_types") Collection<String> authorizationGrantTypes,
                                 @Param("redirect_uris") Collection<String> redirectUris,
                                 @Param("requires_approval") boolean requiresApproval,
                                 @Param("api_version") int apiVersion,
                                 @Param("type") String type);

    @Query("""
    SELECT *
    FROM application_clients
    WHERE id = :id
    """)
    Optional<ApplicationClientEntity> findById(@Param("id") UUID id);
}
