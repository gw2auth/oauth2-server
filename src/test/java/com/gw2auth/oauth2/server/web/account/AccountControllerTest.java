package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.Application;
import com.gw2auth.oauth2.server.WithMockGw2AuthUser;
import com.gw2auth.oauth2.server.WithMockGw2AuthUserSecurityContextFactory;
import com.gw2auth.oauth2.server.configuration.SelfProxyRestConfiguration;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationRepository;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ComponentScan(basePackageClasses = Application.class, excludeFilters = @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = SelfProxyRestConfiguration.class))
class AccountControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AccountFederationRepository accountFederationRepository;

    @Test
    public void getAccountSummaryUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/summary"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockGw2AuthUser
    public void getAccountSummary() throws Exception {
        this.mockMvc.perform(get("/api/account/summary"))
                .andExpect(status().isOk());
    }

    @Test
    public void getAccountFederationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/account/federation"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockGw2AuthUser
    public void getAccountFederations() throws Exception {
        this.mockMvc.perform(get("/api/account/federation"))
                .andExpect(status().isOk());
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

    @Test
    @WithMockGw2AuthUser(issuer = "test", idAtIssuer = "test")
    public void deleteAccountFederationCurrentFederation() throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test")
                        .with(csrf())
        ).andExpect(status().isBadRequest());
    }

    @Test
    @WithMockGw2AuthUser
    public void deleteAccountFederationHavingLessThan2() throws Exception {
        this.mockMvc.perform(
                delete("/api/account/federation")
                        .queryParam("issuer", "test")
                        .queryParam("idAtIssuer", "test2")
                        .with(csrf())
        ).andExpect(status().isNotAcceptable());
    }

    @Test
    public void deleteAccountFederation() throws Exception {
        final AccountEntity accountEntity = this.accountRepository.save(new AccountEntity(null, Instant.now()));

        WithMockGw2AuthUserSecurityContextFactory.withMockGw2AuthUser(accountEntity.id(), "issuer", "idAtIssuer");

        this.accountFederationRepository.save(new AccountFederationEntity("issuer", "idAtIssuer", accountEntity.id()));
        this.accountFederationRepository.save(new AccountFederationEntity("issuer2", "idAtIssuer2", accountEntity.id()));

        this.mockMvc.perform(
                delete("/api/account/federation")
                        .queryParam("issuer", "issuer2")
                        .queryParam("idAtIssuer", "idAtIssuer2")
                        .with(csrf())
        ).andExpect(status().isOk());

        final List<AccountFederationEntity> result = this.accountFederationRepository.findAllByAccountId(accountEntity.id());
        assertEquals(1, result.size());
        assertEquals(new AccountFederationEntity("issuer", "idAtIssuer", accountEntity.id()), result.get(0));
    }
}