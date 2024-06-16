package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.*;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    private TestHelper testHelper;

    @ParameterizedTest
    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationUnknownProvider(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(get("/api/account/federation/{provider}", UUID.randomUUID().toString()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
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

    @ParameterizedTest
    @WithGw2AuthLogin(issuer = "dummyIssuer", idAtIssuer = "A")
    public void addAccountFederationAlreadyLinkedToOtherAccount(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.accountFederationRepository.save("dummyIssuer", "B", otherUserAccountId);

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