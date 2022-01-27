package com.gw2auth.oauth2.server.repository.apisubtoken;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface ApiSubTokenRepository extends BaseRepository<ApiSubTokenEntity> {

    @Override
    default ApiSubTokenEntity save(ApiSubTokenEntity entity) {
        return save(entity.accountId(), entity.gw2AccountId(), entity.gw2ApiPermissionsBitSet(), entity.gw2ApiSubtoken(), entity.expirationTime());
    }

    @Query("""
    INSERT INTO gw2_api_subtokens
    (account_id, gw2_account_id, gw2_api_permissions_bit_set, gw2_api_subtoken, expiration_time)
    VALUES
    (:account_id, :gw2_account_id, :gw2_api_permissions_bit_set, :gw2_api_subtoken, :expiration_time)
    ON CONFLICT (account_id, gw2_account_id, gw2_api_permissions_bit_set) DO UPDATE SET
    gw2_api_subtoken = EXCLUDED.gw2_api_subtoken,
    expiration_time = EXCLUDED.expiration_time
    RETURNING *
    """)
    ApiSubTokenEntity save(@Param("account_id") long accountId,
                           @Param("gw2_account_id") UUID gw2AccountId,
                           @Param("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet,
                           @Param("gw2_api_subtoken") String gw2ApiSubtoken,
                           @Param("expiration_time") Instant expirationTime);

    @Query("""
    SELECT *
    FROM gw2_api_subtokens
    WHERE account_id = :account_id
    AND gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::UUID[])
    AND gw2_api_permissions_bit_set = :gw2_api_permissions_bit_set
    """)
    List<ApiSubTokenEntity> findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(@Param("account_id") long accountId,
                                                                                      @Param("gw2_account_ids") Collection<UUID> gw2AccountIds,
                                                                                      @Param("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet);
}
