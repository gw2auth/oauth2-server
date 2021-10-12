package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import com.gw2auth.oauth2.server.repository.account.AccountFederationEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationRepository;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    private AccountFederationRepository accountFederationRepository;

    @Test
    public void getAccountSummaryUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/summary"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getAccountSummary(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/account/summary").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.apiTokens").value("0"))
                .andExpect(jsonPath("$.verifiedGw2Accounts").value("0"))
                .andExpect(jsonPath("$.clientRegistrations").value("0"))
                .andExpect(jsonPath("$.clientAuthorizations").value("0"))
                .andExpect(jsonPath("$.accountFederations").value("1"));
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
}