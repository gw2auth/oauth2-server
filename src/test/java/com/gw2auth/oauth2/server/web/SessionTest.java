package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.repository.account.AccountFederationSessionEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationSessionRepository;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountServiceImpl;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.util.Constants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;

import java.time.*;
import java.util.List;
import java.util.Map;
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
    private Gw2AuthTokenUserService gw2AuthTokenUserService;

    @Autowired
    private Gw2AuthInternalJwtConverter jwtConverter;

    @Autowired
    private TestHelper testHelper;

    @AfterEach
    public void resetClock() {
        this.accountService.setClock(Clock.systemUTC());
        this.gw2AuthTokenUserService.setClock(Clock.systemUTC());
    }

    @Test
    public void logoutShouldDeleteSession() throws Exception {
        final SessionHandle sessionHandle = new SessionHandle();
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertEquals(1, sessions.size());

        this.gw2AuthLoginExtension.logout(sessionHandle).andExpectAll(this.gw2AuthLoginExtension.expectLogoutSuccess());

        sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }

    @Test
    public void expiredSessionShouldNotBeAccepted() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        this.accountService.setClock(testingClock);

        final SessionHandle sessionHandle = new SessionHandle();
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        // not expired: should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // let 31 days pass
        testingClock = Clock.offset(testingClock, Duration.ofDays(31L));
        this.accountService.setClock(testingClock);

        // expired: should not work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isForbidden());
    }

    @Test
    public void expiredSessionsShouldBeDeleted() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        this.accountService.setClock(testingClock);

        final SessionHandle sessionHandle = new SessionHandle();
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "idAtIssuer").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

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
    public void tryImpersonateOtherAccountWithModifiedJWT(SessionHandle sessionHandle) throws Exception {
        // should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        this.accountService.getOrCreateAccount("second", "someotherid");
        final AccountFederationSession otherUserSession = this.accountService.createNewSession("second", "someotherid");

        final Jwt myJwt = this.jwtConverter.readJWT(sessionHandle.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).getValue());
        final Map<String, Object> sessionMetadata = this.jwtConverter.readSessionMetadata(myJwt).orElseThrow();
        final Jwt otherUsersJwt = this.jwtConverter.writeJWT(otherUserSession.id(), sessionMetadata, otherUserSession.creationTime(), otherUserSession.expirationTime());

        // using the "real" cookie of another user should work too
        sessionHandle.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).setValue(otherUsersJwt.getTokenValue());
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        final String[] myJwtParts = myJwt.getTokenValue().split("\\.");
        final String[] otherUsersJwtParts = otherUsersJwt.getTokenValue().split("\\.");
        final String modifiedJwt = myJwtParts[0] + "." + otherUsersJwtParts[1] + "." + myJwtParts[2];

        // using the modified jwt should not work
        sessionHandle.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME).setValue(modifiedJwt);
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void requestsWithoutLocationShouldFailIfSessionHasLocation(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // using unmodified session handle, should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        sessionHandle.setCountryCode(null);
        sessionHandle.setCity(null);
        sessionHandle.setLatitude(null);
        sessionHandle.setLongitude(null);

        // using modified session handle, request will be made without those headers, should not work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isForbidden());

        // session should be deleted
        final List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }

    @Test
    public void requestsWithShortTravelShouldSucceed() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthTokenUserService.setClock(testingClock);

        // Brandenburger Tor
        final SessionHandle sessionHandle = new SessionHandle("DE", "Berlin", 52.5162778, 13.3755154);

        // login using that location
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "id").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        // using unmodified session handle, should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // set the location to Deutscher Bundestag
        sessionHandle.setLatitude(52.5162843);
        sessionHandle.setLongitude(13.3755154);

        // let 30min pass
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(30L));
        this.gw2AuthTokenUserService.setClock(testingClock);

        // using modified session handle, short travel, should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());
    }

    @Test
    public void requestsWithMediumTravelShortTimeShouldFail() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthTokenUserService.setClock(testingClock);

        // Brandenburger Tor
        final SessionHandle sessionHandle = new SessionHandle("DE", "Berlin", 52.5162778, 13.3755154);

        // login using that location
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "id").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // using unmodified session handle, should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // set the location to Hamburg Hbf (~254.02 km)
        sessionHandle.setCity("Hamburg");
        sessionHandle.setLatitude(53.5529961);
        sessionHandle.setLongitude(10.0021522);

        // let 30min pass
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(30L));
        this.gw2AuthTokenUserService.setClock(testingClock);

        // using modified session handle, medium travel, short time, should not work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isForbidden());

        // session should be deleted
        final List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }

    @Test
    public void requestsWithLongTravelFail2() throws Exception {
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthTokenUserService.setClock(testingClock);

        // Brandenburger Tor
        final SessionHandle sessionHandle = new SessionHandle("DE", "Berlin", 52.5162778, 13.3755154);

        // login using that location
        this.gw2AuthLoginExtension.login(sessionHandle, "issuer", "id").andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess());

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // using unmodified session handle, should work
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // set the location to Times Square, NYC, US
        sessionHandle.setCountryCode("US");
        sessionHandle.setCity("New York");
        sessionHandle.setLatitude(40.7579787);
        sessionHandle.setLongitude(-73.9877313);

        // let 20 days pass
        testingClock = Clock.offset(testingClock, Duration.ofDays(20L));
        this.gw2AuthTokenUserService.setClock(testingClock);

        // using modified session handle, long travel, long time, should not work (long travel should never work)
        this.mockMvc.perform(get("/api/account/summary").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isForbidden());

        // session should be deleted
        final List<AccountFederationSessionEntity> sessions = this.accountFederationSessionRepository.findAllByAccountId(accountId);
        assertTrue(sessions.isEmpty());
    }
}
