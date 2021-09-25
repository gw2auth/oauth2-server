package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import javax.annotation.PostConstruct;
import java.util.Set;

@Profile("local")
@Configuration
public class LocalConfiguration {

    private final AccountService accountService;
    private final RegisteredClientRepository registeredClientRepository;
    private final ClientRegistrationService clientRegistrationService;
    private final JdbcOperations jdbcOperations;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public LocalConfiguration(AccountService accountService, RegisteredClientRepository registeredClientRepository, ClientRegistrationService clientRegistrationService, JdbcOperations jdbcOperations, PasswordEncoder passwordEncoder) {
        this.accountService = accountService;
        this.registeredClientRepository = registeredClientRepository;
        this.clientRegistrationService = clientRegistrationService;
        this.jdbcOperations = jdbcOperations;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initialize() {
        if (this.registeredClientRepository.findByClientId("gw2hub-web") == null) {
            final Account account = this.accountService.getOrCreateAccount("ghost", "ghost");
            final ClientRegistrationCreation clientRegistrationCreation = this.clientRegistrationService.createClientRegistration(account.id(), "Local", Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()), "http://127.0.0.1:8080/login/oauth2/code/gw2hub");

            this.jdbcOperations.update("UPDATE client_registrations SET client_id = ?, client_secret = ? WHERE id = ?", "gw2hub-web", this.passwordEncoder.encode("secret"), clientRegistrationCreation.clientRegistration().id());
        }
    }
}
