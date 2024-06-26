package com.gw2auth.oauth2.server.repository.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AccountRepository extends BaseRepository<AccountEntity> {

    @Override
    default AccountEntity save(AccountEntity account) {
        return save(account.id(), account.creationTime());
    }

    @Query("""
    INSERT INTO accounts
    (id, creation_time)
    VALUES
    (:id, :creation_time)
    RETURNING *
    """)
    AccountEntity save(@Param("id") UUID id, @Param("creation_time") Instant creationTime);

    @Query("SELECT * FROM accounts WHERE id = :id")
    Optional<AccountEntity> findById(@Param("id") UUID id);

    @Query("SELECT acc.* FROM accounts acc INNER JOIN account_federations fed ON acc.id = fed.account_id WHERE fed.issuer = :issuer AND fed.id_at_issuer = :id_at_issuer")
    Optional<AccountEntity> findByFederation(@Param("issuer") String issuer, @Param("id_at_issuer") String idAtIssuer);

    @Query("""
    SELECT
        acc.id AS acc_id,
        acc.creation_time AS acc_creation_time,
        fed_sess.id AS sess_id,
        fed_sess.issuer AS sess_issuer,
        fed_sess.id_at_issuer AS sess_id_at_issuer,
        fed_sess.metadata AS sess_metadata,
        fed_sess.creation_time AS sess_creation_time,
        fed_sess.expiration_time AS sess_expiration_time
    FROM accounts acc
    INNER JOIN account_federations fed
    ON acc.id = fed.account_id
    INNER JOIN account_federation_sessions fed_sess
    ON fed.issuer = fed_sess.issuer AND fed.id_at_issuer = fed_sess.id_at_issuer
    WHERE fed_sess.id = :id AND :now BETWEEN fed_sess.creation_time AND fed_sess.expiration_time
    """)
    Optional<AccountWithSessionEntity> findByFederationSession(@Param("id") String id, @Param("now") Instant now);
}
