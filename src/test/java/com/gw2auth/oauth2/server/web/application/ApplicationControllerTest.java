package com.gw2auth.oauth2.server.web.application;

import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TestHelper;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class ApplicationControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ClientConsentRepository clientConsentRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getApplicationSummary() throws Exception {
        final long accountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();

        final int accounts = 102;
        final int apiTokens = 3;
        final int verifiedGw2Accounts = 5;
        final int clientRegistrations = 12;
        final int clientAuthorizations = 10;// this must be less than clientRegistrations! (only to keep the testcase simple)

        for (int i = 0; i < accounts; i++) {
            this.accountRepository.save(new AccountEntity(null, Instant.now()));
        }

        for (int i = 0; i < apiTokens; i++) {
            this.testHelper.createApiToken(accountId, UUID.randomUUID(), Set.of(), "Name");
        }

        for (int i = 0; i < verifiedGw2Accounts; i++) {
            this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(UUID.randomUUID(), accountId));
        }

        final Queue<ClientRegistrationEntity> clientRegistrationEntities = new LinkedList<>();

        for (int i = 0; i < clientRegistrations; i++) {
            clientRegistrationEntities.add(this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID(), "", Set.of(), Set.of("http://127.0.0.1/"))));
        }

        for (int i = 0; i < clientAuthorizations; i++) {
            this.clientConsentRepository.save(new ClientConsentEntity(accountId, clientRegistrationEntities.poll().id(), UUID.randomUUID(), Set.of("dummy")));
        }

        // add one client authorization without scopes (that should not be counted)
        this.clientConsentRepository.save(new ClientConsentEntity(accountId, clientRegistrationEntities.poll().id(), UUID.randomUUID(), Set.of()));

        this.mockMvc.perform(get("/api/application/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accounts").value(Integer.toString(accounts + 1)))// we create one dummy account who owns everything else
                .andExpect(jsonPath("$.apiTokens").value(Integer.toString(apiTokens)))
                .andExpect(jsonPath("$.verifiedGw2Accounts").value(Integer.toString(verifiedGw2Accounts)))
                .andExpect(jsonPath("$.clientRegistrations").value(Integer.toString(clientRegistrations)))
                .andExpect(jsonPath("$.clientAuthorizations").value(Integer.toString(clientAuthorizations)));
    }
}