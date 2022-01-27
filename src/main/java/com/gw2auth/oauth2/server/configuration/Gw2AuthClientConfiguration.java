package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.configuration.properties.Gw2AuthClientProperties;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Configuration
@EnableConfigurationProperties(Gw2AuthClientProperties.class)
public class Gw2AuthClientConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2AuthClientConfiguration.class);

    private final AccountService accountService;
    private final ClientRegistrationService clientRegistrationService;
    private final JdbcOperations jdbcOperations;
    private final PasswordEncoder passwordEncoder;
    private final Gw2AuthClientProperties properties;

    @Autowired
    public Gw2AuthClientConfiguration(AccountService accountService,
                                      ClientRegistrationService clientRegistrationService,
                                      JdbcOperations jdbcOperations,
                                      PasswordEncoder passwordEncoder,
                                      Gw2AuthClientProperties properties) {

        this.accountService = accountService;
        this.clientRegistrationService = clientRegistrationService;
        this.jdbcOperations = jdbcOperations;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @PostConstruct
    public void initialize() {
        for (Gw2AuthClientProperties.Registration registrationConfig : this.properties.getRegistration()) {
            if (this.clientRegistrationService.getClientRegistration(UUID.fromString(registrationConfig.getClientId())).isEmpty()) {
                final List<Gw2AuthClientProperties.Account> accountsConfig = this.properties.getAccount().get(registrationConfig.getAccount());
                Account account = null;

                for (Gw2AuthClientProperties.Account accountConfig : accountsConfig) {
                    if (account == null) {
                        account = this.accountService.getOrCreateAccount(accountConfig.getIssuer(), accountConfig.getIdAtIssuer());
                    } else {
                        account = this.accountService.addAccountFederationOrReturnExisting(account.id(), accountConfig.getIssuer(), accountConfig.getIdAtIssuer());
                    }
                }

                final ClientRegistrationCreation clientRegistrationCreation = this.clientRegistrationService.createClientRegistration(
                        Objects.requireNonNull(account).id(),
                        registrationConfig.getDisplayName(),
                        registrationConfig.getAuthorizationGrantTypes(),
                        Set.of(registrationConfig.getRedirectUri())
                );

                this.jdbcOperations.update(
                        "UPDATE client_registrations SET client_id = ?, client_secret = ? WHERE id = ?",
                        registrationConfig.getClientId(),
                        this.passwordEncoder.encode(registrationConfig.getClientSecret()),
                        clientRegistrationCreation.clientRegistration().id()
                );

                LOG.debug("Created Gw2Auth Client with client-id={} from configuration", registrationConfig.getClientId());
            } else {
                LOG.debug("Gw2Auth Client with client-id={} already exists", registrationConfig.getClientId());
            }
        }
    }
}
