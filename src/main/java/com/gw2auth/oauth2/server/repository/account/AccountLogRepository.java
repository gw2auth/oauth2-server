package com.gw2auth.oauth2.server.repository.account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.json.JSONObject;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface AccountLogRepository extends BaseRepository<AccountLogEntity>, CustomAccountLogRepository {

    @Override
    default AccountLogEntity save(AccountLogEntity entity) {
        return save(entity.id(), entity.accountId(), entity.timestamp(), entity.message(), entity.fields(), entity.persistent());
    }

    @Query("""
    INSERT INTO account_logs
    (id, account_id, timestamp, message, fields, persistent)
    VALUES
    (:id, :account_id, :timestamp, :message, :fields, :persistent)
    RETURNING *
    """)
    AccountLogEntity save(@Param("id") UUID id,
                          @Param("account_id") UUID accountId,
                          @Param("timestamp") Instant timestamp,
                          @Param("message") String message,
                          @Param("fields") JSONObject fields,
                          @Param("persistent") boolean persistent);

    @Query("""
    SELECT *
    FROM account_logs
    WHERE account_id = :account_id
    AND fields @> :fields
    ORDER BY timestamp DESC
    LIMIT :page_size OFFSET (:page * :page_size)
    """)
    List<AccountLogEntity> findAllByAccountIdAndFields(@Param("account_id") UUID accountId,
                                                       @Param("fields") JSONObject fields,
                                                       @Param("page") int page,
                                                       @Param("page_size") int pageSize);

    @Modifying
    @Query("""
    DELETE FROM account_logs
    WHERE account_id = :account_id
    AND NOT persistent
    AND timestamp <= (
        SELECT timestamp
        FROM account_logs
        WHERE account_id = :account_id
        ORDER BY timestamp DESC
        OFFSET :keep_log_count
        LIMIT 1
    )
    """)
    void deleteAllByAccountIdExceptLatestN(@Param("account_id") UUID accountId, @Param("keep_log_count") int keepLogCount);
}
