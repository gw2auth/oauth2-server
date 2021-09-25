package com.gw2auth.oauth2.server.repository.client.registration;

import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("jdbcClientRegistrationRepository")
public interface ClientRegistrationRepository extends CrudRepository<ClientRegistrationEntity, Long> {

    @Query("SELECT * FROM client_registrations WHERE account_id = :account_id")
    List<ClientRegistrationEntity> findAllByAccountId(@Param("account_id") long accountId);

    @Query("SELECT * FROM client_registrations WHERE account_id = :account_id AND client_id = :client_id")
    Optional<ClientRegistrationEntity> findByAccountIdIdAndClientId(@Param("account_id") long accountId, @Param("client_id") String clientId);

    @Query("SELECT * FROM client_registrations WHERE client_id = :client_id")
    Optional<ClientRegistrationEntity> findByClientId(@Param("client_id") String clientId);

    @Modifying
    @Query("DELETE FROM client_registrations WHERE account_id = :account_id AND client_id = :client_id")
    boolean deleteByAccountIdIdAndClientId(@Param("account_id") long accountId, @Param("client_id") String clientId);
}
