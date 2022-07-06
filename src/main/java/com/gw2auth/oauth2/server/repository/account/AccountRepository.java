package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface AccountRepository extends CrudRepository<AccountEntity, Long> {

    @Query("SELECT acc.* FROM accounts acc INNER JOIN account_federations fed ON acc.id = fed.account_id WHERE fed.issuer = :issuer AND fed.id_at_issuer = :id_at_issuer")
    Optional<AccountEntity> findByFederation(@Param("issuer") String issuer, @Param("id_at_issuer") String idAtIssuer);

    @Query("""
    SELECT acc.*, fed.issuer, fed.id_at_issuer
    FROM accounts acc
    INNER JOIN account_federations fed
    ON acc.id = fed.account_id
    INNER JOIN account_federation_sessions fed_sess
    ON fed.issuer = fed_sess.issuer AND fed.id_at_issuer = fed_sess.id_at_issuer
    WHERE fed_sess.id = :id AND :now BETWEEN fed_sess.creation_time AND fed_sess.expiration_time
    """)
    Optional<AccountWithFederationEntity> findByFederationSession(@Param("id") String id, @Param("now") Instant now);
}
