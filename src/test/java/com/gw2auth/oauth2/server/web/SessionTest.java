package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.adapt.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.repository.account.AccountFederationSessionEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationSessionRepository;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountServiceImpl;
import com.gw2auth.oauth2.server.util.Constants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
public class SessionTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountFederationSessionRepository accountFederationSessionRepository;

    @Autowired
    private AccountServiceImpl accountService;

    @Autowired
    private Gw2AuthInternalJwtConverter jwtConverter;

    @Autowired
    private TestHelper testHelper;

    @AfterEach
    public void resetClock() {
        this.accountService.setClock(Clock.systemUTC());
    }

    @Test
    public void logoutShouldDeleteSession() throws Exception {
        final CookieHolder cookieHolder = new CookieHolder();
        this.gw2AuthLoginExtension.login(cookieHolder, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();

        List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertEquals(1, sessions.size());

        this.gw2AuthLoginExtension.logout(cookieHolder).andExpectAll(this.gw2AuthLoginExtension.expectLogoutSuccess());

        sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }

    @Test
    public void expiredSessionShouldNotBeAccepted() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        this.accountService.setClock(testingClock);

        final CookieHolder cookieHolder = new CookieHolder();
        this.gw2AuthLoginExtension.login(cookieHolder, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        // not expired: should work
        this.mockMvc.perform(get("/api/account/summary").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isOk());

        // let 31 days pass
        testingClock = Clock.offset(testingClock, Duration.ofDays(31L));
        this.accountService.setClock(testingClock);

        // expired: should not work
        this.mockMvc.perform(get("/api/account/summary").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isForbidden());
    }

    @Test
    public void expiredSessionsShouldBeDeleted() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        this.accountService.setClock(testingClock);

        final CookieHolder cookieHolder = new CookieHolder();
        this.gw2AuthLoginExtension.login(cookieHolder, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();

        List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertEquals(1, sessions.size());

        // let 31 days pass
        testingClock = Clock.offset(testingClock, Duration.ofDays(31L));
        this.accountService.setClock(testingClock);

        // trigger deletion
        this.accountService.deleteAllExpiredSessions();

        // should now be empty
        sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }

    @WithGw2AuthLogin(issuer = "first", idAtIssuer = "someid")
    public void tryImpersonateOtherAccountWithModifiedJWT(CookieHolder cookieHolder) throws Exception {
        // should work
        this.mockMvc.perform(get("/api/account/summary").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isOk());

        this.accountService.getOrCreateAccount("second", "someotherid");
        final AccountFederationSession otherUserSession = this.accountService.createNewSession("second", "someotherid");

        final Jwt myJwt = this.jwtConverter.readJWT(cookieHolder.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).getValue());
        final Jwt otherUsersJwt = this.jwtConverter.writeJWT(otherUserSession.id(), otherUserSession.creationTime(), otherUserSession.expirationTime());

        // using the "real" cookie of another user should work too
        cookieHolder.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).setValue(otherUsersJwt.getTokenValue());
        this.mockMvc.perform(get("/api/account/summary").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isOk());

        final String[] myJwtParts = myJwt.getTokenValue().split("\\.");
        final String[] otherUsersJwtParts = otherUsersJwt.getTokenValue().split("\\.");
        final String modifiedJwt = myJwtParts[0] + "." + otherUsersJwtParts[1] + "." + myJwtParts[2];

        // using the modified jwt should not work
        cookieHolder.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).setValue(modifiedJwt);
        this.mockMvc.perform(get("/api/account/summary").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isForbidden());
    }
}
