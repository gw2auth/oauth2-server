package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.stream.Stream;

@Repository
public interface ClientAuthorizationLogRepository extends CrudRepository<ClientAuthorizationLogEntity, Long> {

    @Query("""
    SELECT logs.*
    FROM client_authorization_logs logs
    INNER JOIN client_registrations reg
    ON logs.client_registration_id = reg.id
    WHERE logs.account_id = :account_id AND reg.client_id = :client_id
    ORDER BY logs.timestamp DESC
    LIMIT :page_size OFFSET (:page * :page_size)
    """)
    Stream<ClientAuthorizationLogEntity> findByAccountIdAndClientId(@Param("account_id") long accountId,
                                                                    @Param("client_id") String clientId,
                                                                    @Param("page") int page,
                                                                    @Param("page_size") int pageSize);

    @Modifying
    @Query("DELETE FROM client_authorization_logs WHERE account_id = :account_id AND client_registration_id = :client_registration_id")
    void deleteAllByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);

    @Modifying
    @Query("""
    DELETE FROM client_authorization_logs
    WHERE id IN (
        SELECT id
        FROM client_authorization_logs
        WHERE account_id = :account_id AND client_registration_id = :client_registration_id
        ORDER BY timestamp DESC
        OFFSET :keep_log_count
    )
    """)
    void deleteAllByAccountIdAndClientRegistrationIdExceptLatestN(@Param("account_id") long accountId,
                                                                  @Param("client_registration_id") long clientRegistrationId,
                                                                  @Param("keep_log_count") int keepLogCount);
}
