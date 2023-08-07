package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.*;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
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
    private AccountFederationRepository accountFederationRepository;

    @Autowired
    private AccountFederationSessionRepository accountFederationSessionRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getAccountSummaryUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/summary"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getAccountSummary(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final int apiTokens = 3;
        final int verifiedGw2Accounts = 5;
        final int clientRegistrations = 12;
        final int clientAuthorizations = 10;// this must be less than clientRegistrations! (only to keep the testcase simple)
        final int accountFederations = 2;

        for (int i = 0; i < apiTokens; i++) {
            this.testHelper.createApiToken(accountId, UUID.randomUUID(), "", Set.of(), "Name");
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

        for (int i = 0; i < accountFederations; i++) {
            this.testHelper.createAccountFederation(UUID.randomUUID().toString(), UUID.randomUUID().toString(), accountId);
        }

        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
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
    public void getAccountFederations(SessionHandle sessionHandle) throws Exception {
        final String sessionId = this.testHelper.getSessionIdForCookie(sessionHandle).orElseThrow();

        this.mockMvc.perform(get("/api/account/federation").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentIssuer").value("test-iss"))
                .andExpect(jsonPath("$.currentIdAtIssuer").value("test-id"))
                .andExpect(jsonPath("$.currentSessionId").value(sessionId))
                .andExpect(jsonPath("$.federations").isArray())
                .andExpect(jsonPath("$.federations[0].issuer").value("test-iss"))
                .andExpect(jsonPath("$.federations[0].idAtIssuer").value("test-id"))
                .andExpect(jsonPath("$.federations[0].sessions").isArray())
                .andExpect(jsonPath("$.federations[0].sessions[0].id").value(sessionId))
                .andExpect(jsonPath("$.federations[0].sessions[0].creationTime").isString())
                .andExpect(jsonPath("$.federations[0].sessions[0].expirationTime").isString());
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
    public void deleteAccountFederationCurrentFederation(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .with(sessionHandle)
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test")
                        .with(csrf())
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void deleteAccountFederationHavingLessThan2(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .with(sessionHandle)
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test2")
                        .with(csrf())
        )
                .andDo(sessionHandle)
                .andExpect(status().isNotAcceptable());
    }

    @WithGw2AuthLogin(issuer = "issuer", idAtIssuer = "idAtIssuer")
    public void deleteAccountFederation(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        this.testHelper.createAccountFederation("issuer2", "idAtIssuer2", accountId);

        this.mockMvc.perform(
                delete("/api/account/federation")
                        .with(sessionHandle)
                        .queryParam("issuer", "issuer2")
                        .queryParam("idAtIssuer", "idAtIssuer2")
                        .with(csrf())
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountId);
        assertEquals(1, result.size());
        assertEquals(new AccountFederationEntity("issuer", "idAtIssuer", accountId), result.get(0));
    }

    @Test
    public void deleteSessionUnauthenticated() throws Exception {
        this.mockMvc.perform(
                delete("/api/account/session")
                        .queryParam("id", "")
                        .with(csrf())
        ).andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin(issuer = "test", idAtIssuer = "test")
    public void deleteSessionCurrentSession(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                        delete("/api/account/session")
                                .with(sessionHandle)
                                .queryParam("id", this.testHelper.getSessionIdForCookie(sessionHandle).orElseThrow())
                                .with(csrf())
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin(issuer = "issuer", idAtIssuer = "idAtIssuer")
    public void deleteSession(SessionHandle sessionHandle) throws Exception {
        final SessionHandle otherSessionSessionHandle = new SessionHandle();

        this.gw2AuthLoginExtension.login(otherSessionSessionHandle, "issuer", "otherIdAtIssuer")
                .andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        this.mockMvc.perform(
                        delete("/api/account/session")
                                .with(sessionHandle)
                                .queryParam("id", this.testHelper.getSessionIdForCookie(otherSessionSessionHandle).orElseThrow())
                                .with(csrf())
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        this.mockMvc.perform(head("/api/authinfo").with(otherSessionSessionHandle))
                .andExpect(status().isUnauthorized());

        final List<AccountFederationSessionEntity> result = this.accountFederationSessionRepository.findAllByAccountId(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow());
        assertEquals(1, result.size());
        assertEquals("idAtIssuer", result.get(0).idAtIssuer());
    }

    @Test
    public void deleteAccountUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/account").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteAccount(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        this.mockMvc.perform(delete("/api/account").with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").value("true"));

        // session should be invalidated
        assertTrue(this.testHelper.getAccountIdForCookie(sessionHandle).isEmpty());

        // account should be removed (checking for account is enough, since every other table has a foreign key on that)
        assertTrue(this.accountRepository.findById(accountId).isEmpty());
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationUnknownProvider(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(get("/api/account/federation/{provider}", UUID.randomUUID().toString()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederation(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final String loginURL = this.mockMvc.perform(get("/api/account/federation/{provider}", "dummyIssuer").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().is3xxRedirection())
                .andReturn()
                .getResponse()
                .getRedirectedUrl();

        this.gw2AuthLoginExtension.login(loginURL, "dummyIssuer", "B").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountId);
        assertEquals(2, result.size());
        assertTrue(result.containsAll(List.of(
                new AccountFederationEntity("dummyIssuer", "A", accountId),
                new AccountFederationEntity("dummyIssuer", "B", accountId)
        )));
    }

    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationAlreadyLinkedToOtherAccount(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createAccountFederation("dummyIssuer", "B", otherUserAccountId);

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final String loginURL = this.mockMvc.perform(get("/api/account/federation/{provider}", "dummyIssuer").with(sessionHandle))
                .andDo(sessionHandle)
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