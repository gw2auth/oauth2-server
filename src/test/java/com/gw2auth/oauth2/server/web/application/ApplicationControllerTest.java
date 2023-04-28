package com.gw2auth.oauth2.server.web.application;

import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TestHelper;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
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
    private AccountRepository accountRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getApplicationSummary() throws Exception {
        final UUID accountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();

        final int accounts = 102;
        final int apiTokens = 3;
        final int verifiedGw2Accounts = 5;
        final int clientRegistrations = 12;
        final int clientAuthorizations = 10;// this must be less than clientRegistrations! (only to keep the testcase simple)

        for (int i = 0; i < accounts; i++) {
            this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now()));
        }

        for (int i = 0; i < apiTokens; i++) {
            this.testHelper.createApiToken(accountId, UUID.randomUUID(), Set.of(), "Name");
        }

        for (int i = 0; i < verifiedGw2Accounts; i++) {
            this.testHelper.createAccountVerification(accountId, UUID.randomUUID());
        }

        final Queue<ApplicationClientEntity> applicationClientEntities = new LinkedList<>();

        for (int i = 0; i < clientRegistrations; i++) {
            applicationClientEntities.add(this.testHelper.createClientRegistration(accountId, "Name"));
        }

        for (int i = 0; i < clientAuthorizations; i++) {
            this.testHelper.createClientConsent(accountId, applicationClientEntities.poll().id(), Set.of("dummy"));
        }

        // add one client authorization without scopes (that should not be counted)
        this.testHelper.createClientConsent(accountId, applicationClientEntities.poll().id(), Set.of());

        this.mockMvc.perform(get("/api/application/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accounts").value(Integer.toString(accounts + 1)))// we create one dummy account who owns everything else
                .andExpect(jsonPath("$.apiTokens").value(Integer.toString(apiTokens)))
                .andExpect(jsonPath("$.verifiedGw2Accounts").value(Integer.toString(verifiedGw2Accounts)))
                .andExpect(jsonPath("$.clientRegistrations").value(Integer.toString(clientRegistrations)))
                .andExpect(jsonPath("$.clientAuthorizations").value(Integer.toString(clientAuthorizations)));
    }
}