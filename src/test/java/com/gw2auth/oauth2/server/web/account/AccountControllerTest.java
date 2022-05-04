package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationRepository;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class AccountControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ClientConsentRepository clientConsentRepository;

    @Autowired
    private AccountFederationRepository accountFederationRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getAccountSummaryUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/summary"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getAccountSummary(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final int apiTokens = 3;
        final int verifiedGw2Accounts = 5;
        final int clientRegistrations = 12;
        final int clientAuthorizations = 10;// this must be less than clientRegistrations! (only to keep the testcase simple)
        final int accountFederations = 2;

        for (int i = 0; i < apiTokens; i++) {
            this.testHelper.createApiToken(accountId, UUID.randomUUID(), "", Set.of(), "Name");
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

        for (int i = 0; i < accountFederations; i++) {
            this.accountFederationRepository.save(new AccountFederationEntity(UUID.randomUUID().toString(), UUID.randomUUID().toString(), accountId));
        }

        this.mockMvc.perform(get("/api/account/summary").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.apiTokens").value(Integer.toString(apiTokens)))
                .andExpect(jsonPath("$.verifiedGw2Accounts").value(Integer.toString(verifiedGw2Accounts)))
                .andExpect(jsonPath("$.clientRegistrations").value(Integer.toString(clientRegistrations)))
                .andExpect(jsonPath("$.clientAuthorizations").value(Integer.toString(clientAuthorizations)))
                .andExpect(jsonPath("$.accountFederations").value(Integer.toString(accountFederations + 1)));// one more because WithGw2AuthLogin adds one
    }

    @Test
    public void getAccountFederationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/federation"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin(issuer = "test-iss", idAtIssuer = "test-id")
    public void getAccountFederations(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/account/federation").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentAccountFederation.issuer").value("test-iss"))
                .andExpect(jsonPath("$.currentAccountFederation.idAtIssuer").value("test-id"))
                .andExpect(jsonPath("$.accountFederations").isArray());
    }

    @Test
    public void deleteAccountFederationUnauthenticated() throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .queryParam("issuer", "")
                        .queryParam("idAtIssuer", "")
                        .with(csrf())
        ).andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin(issuer = "test", idAtIssuer = "test")
    public void deleteAccountFederationCurrentFederation(MockHttpSession session) throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .session(session)
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test")
                        .with(csrf())
        ).andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void deleteAccountFederationHavingLessThan2(MockHttpSession session) throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .session(session)
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test2")
                        .with(csrf())
        ).andExpect(status().isNotAcceptable());
    }

    @WithGw2AuthLogin(issuer = "issuer", idAtIssuer = "idAtIssuer")
    public void deleteAccountFederation(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        this.accountFederationRepository.save(new AccountFederationEntity("issuer2", "idAtIssuer2", accountId));

        this.mockMvc.perform(
                delete("/api/account/federation")
                        .session(session)
                        .queryParam("issuer", "issuer2")
                        .queryParam("idAtIssuer", "idAtIssuer2")
                        .with(csrf())
        ).andExpect(status().isOk());

        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountId);
        assertEquals(1, result.size());
        assertEquals(new AccountFederationEntity("issuer", "idAtIssuer", accountId), result.get(0));
    }

    @Test
    public void deleteAccountUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/account").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteAccount(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        this.mockMvc.perform(delete("/api/account").session(session).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value("true"));

        // session should be invalidated
        assertTrue(AuthenticationHelper.getUser(session).isEmpty());

        // account should be removed (checking for account is enough, since every other table has a foreign key on that)
        assertTrue(this.accountRepository.findById(accountId).isEmpty());
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationUnknownProvider(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/account/federation/{provider}", UUID.randomUUID().toString()).session(session))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederation(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String loginURL = this.mockMvc.perform(get("/api/account/federation/{provider}", "dummyIssuer").session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn()
                .getResponse()
                .getRedirectedUrl();

        this.gw2AuthLoginExtension.login(loginURL, "dummyIssuer", "B").andExpectAll(this.gw2AuthLoginExtension.expectSuccess());

        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountId);
        assertEquals(2, result.size());
        assertTrue(result.containsAll(List.of(
                new AccountFederationEntity("dummyIssuer", "A", accountId),
                new AccountFederationEntity("dummyIssuer", "B", accountId)
        )));
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationAlreadyLinkedToOtherAccount(MockHttpSession session) throws Exception {
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();
        this.accountFederationRepository.save(new AccountFederationEntity("dummyIssuer", "B", otherUserAccountId));

        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String loginURL = this.mockMvc.perform(get("/api/account/federation/{provider}", "dummyIssuer").session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn()
                .getResponse()
                .getRedirectedUrl();

        this.gw2AuthLoginExtension.login(loginURL, "dummyIssuer", "B")
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new StringEndsWith("?error")));

        // only the initial federation should be present
        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountId);
        assertEquals(1, result.size());
    }
}