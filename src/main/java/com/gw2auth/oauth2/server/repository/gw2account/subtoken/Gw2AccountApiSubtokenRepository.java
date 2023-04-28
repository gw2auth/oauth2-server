package com.gw2auth.oauth2.server.repository.gw2account.subtoken;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface Gw2AccountApiSubtokenRepository extends BaseRepository<Gw2AccountApiSubtokenEntity>, CustomGw2AccountApiSubtokenRepository {

    @Query("""
    SELECT *
    FROM gw2_account_api_subtokens
    WHERE account_id = :account_id
    AND gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::UUID[])
    AND gw2_api_permissions_bit_set = :gw2_api_permissions_bit_set
    """)
    List<Gw2AccountApiSubtokenEntity> findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(@Param("account_id") UUID accountId,
                                                                                                @Param("gw2_account_ids") Collection<UUID> gw2AccountIds,
                                                                                                @Param("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet);
}
