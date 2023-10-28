package com.gw2auth.oauth2.server.repository.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface AccountFederationSessionRepository extends BaseRepository<AccountFederationSessionEntity> {

    @Override
    default AccountFederationSessionEntity save(AccountFederationSessionEntity accountFederationSessionEntity) {
        return save(
                accountFederationSessionEntity.id(),
                accountFederationSessionEntity.issuer(),
                accountFederationSessionEntity.idAtIssuer(),
                accountFederationSessionEntity.metadata(),
                accountFederationSessionEntity.creationTime(),
                accountFederationSessionEntity.expirationTime()
        );
    }

    @Query("""
    INSERT INTO account_federation_sessions
    (id, issuer, id_at_issuer, metadata, creation_time, expiration_time)
    VALUES
    (:id, :issuer, :id_at_issuer, :metadata, :creation_time, :expiration_time)
    ON CONFLICT (id) DO UPDATE SET
    issuer = EXCLUDED.issuer,
    id_at_issuer = EXCLUDED.id_at_issuer,
    creation_time = EXCLUDED.creation_time,
    expiration_time = EXCLUDED.expiration_time
    RETURNING *
    """)
    AccountFederationSessionEntity save(@Param("id") String id,
                                        @Param("issuer") String issuer,
                                        @Param("id_at_issuer") String idAtIssuer,
                                        @Param("metadata") byte[] metadata,
                                        @Param("creation_time") Instant creationTime,
                                        @Param("expiration_time") Instant expirationTime);

    @Query("""
    INSERT INTO account_federation_sessions
    (id, issuer, id_at_issuer, metadata, creation_time, expiration_time)
    VALUES
    (:id, :issuer, :id_at_issuer, :metadata, :creation_time, :expiration_time)
    ON CONFLICT (id) DO UPDATE SET
    issuer = EXCLUDED.issuer,
    id_at_issuer = EXCLUDED.id_at_issuer,
    metadata = EXCLUDED.metadata,
    expiration_time = EXCLUDED.expiration_time
    RETURNING *
    """)
    AccountFederationSessionEntity updateSession(@Param("id") String id,
                                                 @Param("issuer") String issuer,
                                                 @Param("id_at_issuer") String idAtIssuer,
                                                 @Param("metadata") byte[] metadata,
                                                 @Param("creation_time") Instant creationTime,
                                                 @Param("expiration_time") Instant expirationTime);

    @Query("""
    SELECT fed_sess.*
    FROM account_federation_sessions fed_sess
    INNER JOIN account_federations fed
    ON fed_sess.issuer = fed.issuer AND fed_sess.id_at_issuer = fed.id_at_issuer
    WHERE fed.account_id = :account_id AND NOW() BETWEEN fed_sess.creation_time AND fed_sess.expiration_time
    """)
    List<AccountFederationSessionEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Modifying
    @Query("""
    DELETE FROM account_federation_sessions
    WHERE id = :id
    AND EXISTS(
        SELECT TRUE
        FROM account_federation_sessions fed_sess
        INNER JOIN account_federations fed
        ON fed_sess.issuer = fed.issuer AND fed_sess.id_at_issuer = fed.id_at_issuer
        WHERE fed.account_id = :account_id
    )
    """)
    boolean deleteByAccountIdAndId(@Param("account_id") UUID accountId, @Param("id") String id);

    @Modifying
    @Query("""
    DELETE FROM account_federation_sessions
    WHERE expiration_time <= :now
    """)
    int deleteAllExpired(@Param("now") Instant now);
}
