package com.gw2auth.oauth2.server.repository.client.consent;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@Repository
public interface ClientConsentLogRepository extends BaseRepository<ClientConsentLogEntity> {

    @Override
    default ClientConsentLogEntity save(ClientConsentLogEntity entity) {
        return save(entity.id(), entity.accountId(), entity.clientRegistrationId(), entity.timestamp(), entity.type(), entity.messages());
    }

    @Query("""
    INSERT INTO client_consent_logs
    (id, account_id, client_registration_id, timestamp, type, messages)
    VALUES
    (:id, :account_id, :client_registration_id, :timestamp, :type, ARRAY[ :messages ]::TEXT[])
    RETURNING *
    """)
    ClientConsentLogEntity save(@Param("id") UUID id,
                                @Param("account_id") UUID accountId,
                                @Param("client_registration_id") UUID clientRegistrationId,
                                @Param("timestamp") Instant timestamp,
                                @Param("type") String type,
                                @Param("messages") List<String> messages);

    @Query("""
    SELECT *
    FROM client_consent_logs
    WHERE account_id = :account_id AND client_registration_id = :client_registration_id
    ORDER BY timestamp DESC
    LIMIT :page_size OFFSET (:page * :page_size)
    """)
    Stream<ClientConsentLogEntity> findByAccountIdAndClientRegistrationId(@Param("account_id") UUID accountId,
                                                                          @Param("client_registration_id") UUID clientRegistrationId,
                                                                          @Param("page") int page,
                                                                          @Param("page_size") int pageSize);

    @Modifying
    @Query("""
    DELETE FROM client_consent_logs
    WHERE account_id = :account_id
    AND client_registration_id = :client_registration_id
    AND timestamp <= (
        SELECT timestamp
        FROM client_consent_logs
        WHERE account_id = :account_id
        AND client_registration_id = :client_registration_id
        ORDER BY timestamp DESC
        OFFSET :keep_log_count
        LIMIT 1
    )
    """)
    void deleteAllByAccountIdAndClientRegistrationIdExceptLatestN(@Param("account_id") UUID accountId,
                                                                  @Param("client_registration_id") UUID clientRegistrationId,
                                                                  @Param("keep_log_count") int keepLogCount);
}
