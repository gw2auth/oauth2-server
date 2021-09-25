package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends CrudRepository<AccountEntity, Long> {

    @Query("SELECT acc.* FROM accounts acc INNER JOIN account_federations fed ON acc.id = fed.account_id WHERE fed.issuer = :issuer AND fed.id_at_issuer = :id_at_issuer")
    Optional<AccountEntity> findByFederation(@Param("issuer") String issuer, @Param("id_at_issuer") String idAtIssuer);
}
