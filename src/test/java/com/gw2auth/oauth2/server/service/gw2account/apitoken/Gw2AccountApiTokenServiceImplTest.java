package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONObject;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.EnumSet;
import java.util.Map;
import java.util.UUID;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.RequestMatchers.matchAuthorizedRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class Gw2AccountApiTokenServiceImplTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthClockedExtension gw2AuthClockedExtension;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @Autowired
    private TestHelper testHelper;

    @Autowired
    private Gw2AccountApiTokenServiceImpl gw2AccountApiTokenService;

    @Autowired
    private Gw2AccountRepository gw2AccountRepository;

    @Autowired
    private Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;

    @ParameterizedTest
    @WithGw2AuthLogin
    public void checkTokenValidityWithUpdatedGw2AccountNames(SessionHandle sessionHandle) {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();

        // create new token (also creates the account entity)
        this.testHelper.createApiToken(
                accountId,
                gw2AccountId,
                gw2ApiToken,
                EnumSet.of(Gw2ApiPermission.ACCOUNT),
                "Felix.9127 (Main)",
                "Felix.9127 (Main)"
        );

        // verify the expected values are present in the DB
        Gw2AccountEntity gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // prepare the mock server for the upcoming account request
        this.gw2RestServer.expect(times(1), requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(matchAuthorizedRequest(gw2ApiToken))
                .andRespond((request) -> {
                    final JSONObject responseJson = new JSONObject(Map.of(
                            "id", gw2AccountId.toString(),
                            "name", "Felix.9127"
                    ));
                    final MockClientHttpResponse response = new MockClientHttpResponse(
                            responseJson.toString().getBytes(StandardCharsets.UTF_8),
                            HttpStatus.OK
                    );
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });

        // simulate 4hrs passed (token verification happens every 3h - see application.yml for test)
        final Instant now = Instant.now().plus(Duration.ofHours(4L));
        this.gw2AuthClockedExtension.setClock(Clock.fixed(now, ZoneId.systemDefault()));

        // trigger validity check
        this.gw2AccountApiTokenService.refreshTokenValidityAndAccountName();

        // verify the account name was updated
        gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // verify the token was marked as valid
        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntity = this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertInstantEquals(now, gw2AccountApiTokenEntity.lastValidCheckTime());
        assertInstantEquals(now, gw2AccountApiTokenEntity.lastValidTime());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void checkTokenValidityWithFailingGw2ApiRequest(SessionHandle sessionHandle) {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();

        // create new token (also creates the account entity)
        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntityOld = this.testHelper.createApiToken(
                accountId,
                gw2AccountId,
                gw2ApiToken,
                EnumSet.of(Gw2ApiPermission.ACCOUNT),
                "Felix.9127 (Main)",
                "Felix.9127 (Main)"
        ).v2();

        // verify the expected values are present in the DB
        Gw2AccountEntity gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // prepare the mock server for the upcoming account request
        this.gw2RestServer.expect(times(1), requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(matchAuthorizedRequest(gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(
                            "{}".getBytes(StandardCharsets.UTF_8),
                            HttpStatus.INTERNAL_SERVER_ERROR
                    );
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });

        // simulate 4hrs passed (token verification happens every 3h - see application.yml for test)
        final Instant now = Instant.now().plus(Duration.ofHours(4L));
        this.gw2AuthClockedExtension.setClock(Clock.fixed(now, ZoneId.systemDefault()));

        // trigger validity check
        this.gw2AccountApiTokenService.refreshTokenValidityAndAccountName();

        // account name should not be updated
        gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // verify neither times were updated
        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntityNew = this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertInstantEquals(gw2AccountApiTokenEntityOld.lastValidCheckTime(), gw2AccountApiTokenEntityNew.lastValidCheckTime());
        assertInstantEquals(gw2AccountApiTokenEntityOld.lastValidTime(), gw2AccountApiTokenEntityNew.lastValidTime());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void checkTokenValidityWithInvalidApiToken(SessionHandle sessionHandle) {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();

        // create new token (also creates the account entity)
        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntityOld = this.testHelper.createApiToken(
                accountId,
                gw2AccountId,
                gw2ApiToken,
                EnumSet.of(Gw2ApiPermission.ACCOUNT),
                "Felix.9127 (Main)",
                "Felix.9127 (Main)"
        ).v2();

        // verify the expected values are present in the DB
        Gw2AccountEntity gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // prepare the mock server for the upcoming account request
        this.gw2RestServer.expect(times(1), requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(matchAuthorizedRequest(gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(
                            "{}".getBytes(StandardCharsets.UTF_8),
                            HttpStatus.UNAUTHORIZED
                    );
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });

        // simulate 4hrs passed (token verification happens every 3h - see application.yml for test)
        final Instant now = Instant.now().plus(Duration.ofHours(4L));
        this.gw2AuthClockedExtension.setClock(Clock.fixed(now, ZoneId.systemDefault()));

        // trigger validity check
        this.gw2AccountApiTokenService.refreshTokenValidityAndAccountName();

        // account name should not be updated
        gw2AccountEntity = this.gw2AccountRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.gw2AccountName());
        assertEquals("Felix.9127 (Main)", gw2AccountEntity.displayName());

        // verify only the check time was updated
        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntityNew = this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow();
        assertInstantEquals(now, gw2AccountApiTokenEntityNew.lastValidCheckTime());
        assertInstantEquals(gw2AccountApiTokenEntityOld.lastValidTime(), gw2AccountApiTokenEntityNew.lastValidTime());
    }
}