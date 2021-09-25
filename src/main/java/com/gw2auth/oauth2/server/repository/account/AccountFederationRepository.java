package com.gw2auth.oauth2.server.repository.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AccountFederationRepository extends BaseRepository<AccountFederationEntity> {

    @Override
    default AccountFederationEntity save(AccountFederationEntity accountFederationEntity) {
        return save(accountFederationEntity.issuer(), accountFederationEntity.idAtIssuer(), accountFederationEntity.accountId());
    }

    @Query("""
    INSERT INTO account_federations
    (issuer, id_at_issuer, account_id)
    VALUES
    (:issuer, :id_at_issuer, :account_id)
    RETURNING *
    """)
    AccountFederationEntity save(@Param("issuer") String issuer, @Param("id_at_issuer") String idAtIssuer, @Param("account_id") long accountId);

    @Query("""
    SELECT *
    FROM account_federations
    WHERE account_id = :account_id
    """)
    List<AccountFederationEntity> findAllByAccountId(@Param("account_id") long accountId);
}
