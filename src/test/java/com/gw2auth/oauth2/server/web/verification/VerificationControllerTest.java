package com.gw2auth.oauth2.server.web.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.verification.VerificationChallengeStart;
import com.gw2auth.oauth2.server.service.verification.VerificationServiceImpl;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class VerificationControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestHelper testHelper;

    @Autowired
    private Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private VerificationServiceImpl verificationService;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @AfterEach
    public void resetClock() {
        this.verificationService.setClock(Clock.systemUTC());
    }

    @Test
    public void getBootstrapUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/verification/bootstrap"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getBootstrap(SessionHandle sessionHandle) throws Exception {
        // this basically tests 3 other endpoints too

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ObjectMapper mapper = new ObjectMapper();

        // 1 started challenge
        final String expectedApiTokenName = "ApiTokenName";
        final Gw2AccountVerificationChallengeEntity startedChallenge = this.gw2AccountVerificationChallengeRepository.save(new Gw2AccountVerificationChallengeEntity(accountId, "", 1L, expectedApiTokenName, null, Instant.now(), Instant.now()));

        // 2 pending challenges
        final Gw2AccountVerificationChallengeEntity pendingChallengeA = this.gw2AccountVerificationChallengeRepository.save(new Gw2AccountVerificationChallengeEntity(accountId, UUID.randomUUID().toString(), 1L, expectedApiTokenName + "A", UUID.randomUUID().toString(), Instant.now(), Instant.now().plus(Duration.ofMinutes(30L))));
        final Gw2AccountVerificationChallengeEntity pendingChallengeB = this.gw2AccountVerificationChallengeRepository.save(new Gw2AccountVerificationChallengeEntity(accountId, UUID.randomUUID().toString(), 1L, expectedApiTokenName + "B", UUID.randomUUID().toString(), Instant.now(), Instant.now().plus(Duration.ofMinutes(30L))));

        // 1 verification failed challenge (this should not be part of the pending challenges)
        this.gw2AccountVerificationChallengeRepository.save(new Gw2AccountVerificationChallengeEntity(accountId, UUID.randomUUID().toString(), -1L, null, null, Instant.now(), Instant.now().plus(Duration.ofHours(2L))));

        final String responseJson = this.mockMvc.perform(get("/api/verification/bootstrap").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        final JsonNode responseNode = mapper.readTree(responseJson);
        assertTrue(responseNode.isObject());

        final JsonNode availableChallengesNode = responseNode.get("availableChallenges");
        assertTrue(availableChallengesNode.isArray());

        long previousChallengeId = Long.MIN_VALUE;

        for (int i = 0; i < availableChallengesNode.size(); i++) {
            final JsonNode availableChallengeNode = availableChallengesNode.get(i);
            assertTrue(availableChallengeNode.get("id").isIntegralNumber());

            final long challengeId = availableChallengeNode.get("id").longValue();

            assertTrue(challengeId > previousChallengeId);
            assertTrue(availableChallengeNode.get("requiredGw2ApiPermissions").isArray());

            previousChallengeId = challengeId;
        }

        final JsonNode startedChallengeNode = responseNode.get("startedChallenge");
        assertEquals(startedChallenge.challengeId(), startedChallengeNode.get("challengeId").longValue());
        assertEquals(expectedApiTokenName, startedChallengeNode.get("message").get("apiTokenName").textValue());
        assertInstantEquals(startedChallenge.timeoutAt(), startedChallengeNode.get("nextAllowedStartTime").textValue());

        final JsonNode pendingChallengesNode = responseNode.get("pendingChallenges");
        assertTrue(pendingChallengesNode.isArray());

        final Map<String, Gw2AccountVerificationChallengeEntity> expectedPendingChallenges = new HashMap<>(Map.of(
                pendingChallengeA.gw2AccountId(), pendingChallengeA,
                pendingChallengeB.gw2AccountId(), pendingChallengeB
        ));

        for (int i = 0; i < pendingChallengesNode.size(); i++) {
            final JsonNode pendingChallengeNode = pendingChallengesNode.get(i);
            final String gw2AccountId = pendingChallengeNode.get("gw2AccountId").textValue();
            final Gw2AccountVerificationChallengeEntity challenge = expectedPendingChallenges.remove(gw2AccountId);
            assertNotNull(challenge);

            assertEquals(challenge.challengeId(), pendingChallengeNode.get("challengeId").longValue());
            assertInstantEquals(challenge.startedAt(), pendingChallengeNode.get("startedAt").textValue());
        }

        assertTrue(expectedPendingChallenges.isEmpty());
    }

    @Test
    public void startNewChallengeUnauthenticated() throws Exception {
        this.mockMvc.perform(
                post("/api/verification")
                        .with(csrf())
                        .queryParam("challengeId", "1")
        )
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void startNewChallengeUnknownChallengeId(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                post("/api/verification")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("challengeId", "100")
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void startNewChallengeApiTokenName(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        this.mockMvc.perform(
                post("/api/verification")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("challengeId", "1")
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("1"))
                .andExpect(jsonPath("$.message.apiTokenName").isString())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isPresent());
    }

    @WithGw2AuthLogin
    public void startNewChallengeTPBuyOrder(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        this.mockMvc.perform(
                post("/api/verification")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("challengeId", "2")
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("2"))
                .andExpect(jsonPath("$.message.gw2ItemId").isNumber())
                .andExpect(jsonPath("$.message.buyOrderCoins").isNumber())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isPresent());
    }

    @WithGw2AuthLogin
    public void startNewChallengeCharacterName(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "3")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("3"))
                .andExpect(jsonPath("$.message.characterName").isString())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isPresent());
    }

    @WithGw2AuthLogin
    public void submitChallengeNotExisting(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", UUID.randomUUID().toString())
        )
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void startAndSubmitApiTokenNameChallengeWithInsufficientPermissions(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = UUID.randomUUID().toString();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(), testingClock.instant(), Duration.ofMinutes(90L));

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);

        // start the challenge
        this.verificationService.startChallenge(accountId, 1L);

        // submit the challenge
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());

        // started challenge should not be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isPresent());
    }

    @WithGw2AuthLogin
    public void startAndSubmitApiTokenNameChallengeUnfulfilled(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // start the challenge
        this.verificationService.startChallenge(accountId, 1L);

        // submit the challenge
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("false"))
                .andExpect(jsonPath("$.pending").isMap());

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should be inserted
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isPresent());

        // let 91 minutes pass
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(91L));
        this.verificationService.setClock(testingClock);

        // prepare the api again
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // simulate scheduled check
        this.verificationService.tryVerifyAllPending();

        // pending challenge should be removed
        final Gw2AccountVerificationChallengeEntity verificationChallengeEntity = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).orElse(null);
        assertNull(verificationChallengeEntity);
    }

    @WithGw2AuthLogin
    public void startAndSubmitApiTokenNameChallengeLaterFulfilled(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();

        // insert an api token for another account but for the same gw2 account id
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name");

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // start the challenge
        final VerificationChallengeStart challengeStart = this.verificationService.startChallenge(accountId, 1L);

        // submit the challenge
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("false"))
                .andExpect(jsonPath("$.pending").isMap());

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should be inserted
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isPresent());

        // let 15 minutes pass
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(15L));
        this.verificationService.setClock(testingClock);

        // prepare the api again and now set the name to the requested one
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, challengeStart.message().get("apiTokenName").toString(), Set.of(Gw2ApiPermission.ACCOUNT));

        // simulate scheduled check
        this.verificationService.tryVerifyAllPending();

        // pending challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isEmpty());

        // account should now be verified
        final Gw2AccountVerificationEntity accountVerification = this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).orElse(null);
        assertNotNull(accountVerification);
        assertEquals(accountId, accountVerification.accountId());

        // the other users api token should be removed
        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(otherUserAccountId, gw2AccountId).isEmpty());
    }

    @WithGw2AuthLogin
    public void startAndSubmitApiTokenNameChallengeDirectlyFulfilled(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();

        // insert an api token for another account but for the same gw2 account id
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name");

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // start the challenge
        final VerificationChallengeStart challengeStart = this.verificationService.startChallenge(accountId, 1L);

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, challengeStart.message().get("apiTokenName").toString(), Set.of(Gw2ApiPermission.ACCOUNT));

        // submit the challenge
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("true"));

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should not be present (either removed or never inserted)
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isEmpty());

        // account should now be verified
        final Gw2AccountVerificationEntity accountVerification = this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).orElse(null);
        assertNotNull(accountVerification);
        assertEquals(accountId, accountVerification.accountId());

        // the other users api token should be removed
        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(otherUserAccountId, gw2AccountId).isEmpty());
    }

    @WithGw2AuthLogin
    public void startAndSubmitTPBuyOrderChallengeDirectlyFulfilled(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();

        // insert an api token for another account but for the same gw2 account id
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name");

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST), testingClock.instant(), Duration.ofMinutes(15L));

        // start the challenge
        final VerificationChallengeStart challengeStart = this.verificationService.startChallenge(accountId, 2L);

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST), testingClock.instant().plus(Duration.ofMinutes(15L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTransactionsRequest(gw2ApiSubtoken, 20, (int) challengeStart.message().get("gw2ItemId"), 1, (long) challengeStart.message().get("buyOrderCoins"), testingClock.instant());

        // submit the challenge
        this.mockMvc.perform(
                post("/api/verification/pending")
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("token", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("true"));

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should not be present (either removed or never inserted)
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isEmpty());

        // account should now be verified
        final Gw2AccountVerificationEntity accountVerification = this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).orElse(null);
        assertNotNull(accountVerification);
        assertEquals(accountId, accountVerification.accountId());

        // the other users api token should be removed
        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(otherUserAccountId, gw2AccountId).isEmpty());
    }

    @WithGw2AuthLogin
    public void startAndSubmitCharacterNameChallengeDirectlyFulfilled(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();

        // insert an api token for another account but for the same gw2 account id
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name");

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.CHARACTERS), testingClock.instant(), Duration.ofMinutes(15L));

        // start the challenge
        final VerificationChallengeStart challengeStart = this.verificationService.startChallenge(accountId, 3L);

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.CHARACTERS), testingClock.instant().plus(Duration.ofMinutes(15L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForCharactersRequest(gw2ApiSubtoken, 20, (String) challengeStart.message().get("characterName"));

        // submit the challenge
        this.mockMvc.perform(
                        post("/api/verification/pending")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("token", gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("true"));

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should not be present (either removed or never inserted)
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isEmpty());

        // account should now be verified
        final Gw2AccountVerificationEntity accountVerification = this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).orElse(null);
        assertNotNull(accountVerification);
        assertEquals(accountId, accountVerification.accountId());

        // the other users api token should be removed
        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(otherUserAccountId, gw2AccountId).isEmpty());
    }

    @WithGw2AuthLogin
    public void startChallengeWithoutWaitingLongEnoughBetween(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "1")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("1"))
                .andExpect(jsonPath("$.message.apiTokenName").isString())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        final Gw2AccountVerificationChallengeEntity startedChallenge = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null);
        assertNotNull(startedChallenge);

        // wait 29min (not enough)
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(29L));
        this.verificationService.setClock(testingClock);

        // try to start a new challenge
        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "2")
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());

        // started challenge should not be modified
        assertEquals(startedChallenge, this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null));
    }

    @WithGw2AuthLogin
    public void startChallengeWithSameChallengeIdAsExisting(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "1")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("1"))
                .andExpect(jsonPath("$.message.apiTokenName").isString())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        final Gw2AccountVerificationChallengeEntity startedChallenge = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null);
        assertNotNull(startedChallenge);

        // wait 31min (enough)
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.verificationService.setClock(testingClock);

        // try to start a new challenge
        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "1")
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());

        // started challenge should not be modified
        assertEquals(startedChallenge, this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null));
    }

    @WithGw2AuthLogin
    public void startChallengeWithLongEnoughBetween(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "1")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("1"))
                .andExpect(jsonPath("$.message.apiTokenName").isString())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        final Gw2AccountVerificationChallengeEntity startedChallenge = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null);
        assertNotNull(startedChallenge);

        // wait 29min (not enough)
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.verificationService.setClock(testingClock);

        // try to start a new challenge
        this.mockMvc.perform(
                        post("/api/verification")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("challengeId", "2")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").value("2"))
                .andExpect(jsonPath("$.message.gw2ItemId").isNumber())
                .andExpect(jsonPath("$.message.buyOrderCoins").isNumber())
                .andExpect(jsonPath("$.nextAllowedStartTime").isString());

        // started challenge should be modified
        final Gw2AccountVerificationChallengeEntity updatedStartedChallenge = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").orElse(null);

        assertNotNull(updatedStartedChallenge);
        assertNotEquals(startedChallenge, updatedStartedChallenge);
    }

    @WithGw2AuthLogin
    public void startAndSubmitChallengeForGw2AccountHavingAPendingVerification(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // start the challenge
        this.verificationService.startChallenge(accountId, 1L);

        // submit the challenge
        this.mockMvc.perform(
                        post("/api/verification/pending")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("token", gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("false"))
                .andExpect(jsonPath("$.pending").isMap());

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should be inserted
        final Gw2AccountVerificationChallengeEntity startedChallenge = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).orElse(null);
        assertNotNull(startedChallenge);

        // start a new challenge
        this.verificationService.startChallenge(accountId, 1L);

        // prepare the gw2 api again
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // submit the challenge again (for the same gw2 account)
        this.mockMvc.perform(
                        post("/api/verification/pending")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("token", gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());

        // pending challenge should not be modified
        assertEquals(startedChallenge, this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).orElse(null));
    }

    @WithGw2AuthLogin
    public void startAndSubmitChallengeForGw2AccountAlreadyVerified(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = UUID.randomUUID().toString();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // insert the verification
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // start the challenge
        this.verificationService.startChallenge(accountId, 1L);

        // submit the challenge
        this.mockMvc.perform(
                        post("/api/verification/pending")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("token", gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void startSubmitAndCancelChallenge(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();

        // insert an api token for another account but for the same gw2 account id
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name");

        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // prepare the testing clock
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.verificationService.setClock(testingClock);

        final String gw2ApiToken = TestHelper.randomRootToken();
        final String gw2ApiSubtoken = TestHelper.createSubtokenJWT(UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(90L));

        // start the challenge
        final VerificationChallengeStart challengeStart = this.verificationService.startChallenge(accountId, 1L);

        // prepare the gw2 api
        this.gw2RestServer.reset();
        preparedGw2RestServerForCreateSubtoken(gw2ApiToken, gw2ApiSubtoken, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant().plus(Duration.ofMinutes(90L)));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiSubtoken);
        prepareGw2RestServerForTokenInfoRequest(gw2ApiSubtoken, "Not the name that was requested", Set.of(Gw2ApiPermission.ACCOUNT));

        // submit the challenge
        this.mockMvc.perform(
                        post("/api/verification/pending")
                                .with(sessionHandle)
                                .with(csrf())
                                .queryParam("token", gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isSuccess").value("false"));

        // started challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "").isEmpty());

        // pending challenge should be present
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isPresent());

        // cancel the challenge
        this.mockMvc.perform(
                        delete("/api/verification/pending/{gw2AccountId}", gw2AccountId)
                                .with(sessionHandle)
                                .with(csrf())
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // account should not be verified
        final Gw2AccountVerificationEntity accountVerification = this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).orElse(null);
        assertNull(accountVerification);

        // the other users api token should not be removed
        assertFalse(this.apiTokenRepository.findByAccountIdAndGw2AccountId(otherUserAccountId, gw2AccountId).isEmpty());

        // the challenge should be removed
        assertTrue(this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).isEmpty());
    }

    private void prepareGw2RestServerForTransactionsRequest(String gw2ApiToken, int addDummyValues, int itemId, int quantity, long price, Instant created) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/commerce/transactions/current/buys")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> {
                    final org.json.JSONArray result = new org.json.JSONArray();

                    for (int i = 0; i < addDummyValues; i++) {
                        result.put(new JSONObject(Map.of(
                                "item_id", ThreadLocalRandom.current().nextInt(100_000),
                                "quantity", ThreadLocalRandom.current().nextInt(250),
                                "price", ThreadLocalRandom.current().nextLong(100L * 100L * 2500L),
                                "created", Instant.now().plusMillis(ThreadLocalRandom.current().nextLong(-1000L * 60L * 60L * 24L * 7L, 1000L * 60L * 60L * 24L * 7L)).toString()
                        )));
                    }

                    if (itemId > 0L) {
                        result.put(new JSONObject(Map.of(
                                "item_id", itemId,
                                "quantity", quantity,
                                "price", price,
                                "created", created.toString()
                        )));
                    }

                    final MockClientHttpResponse response = new MockClientHttpResponse(result.toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }

    private void prepareGw2RestServerForTokenInfoRequest(String gw2ApiToken, String apiTokenName, Set<Gw2ApiPermission> gw2ApiPermissions) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/tokeninfo")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of(
                            "name", apiTokenName,
                            "permissions", gw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toList())
                    )).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);

                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }

    private void prepareGw2RestServerForCharactersRequest(String gw2ApiToken, int addDummyValues, String character) {
        final List<String> characters = new ArrayList<>(addDummyValues + 1);

        for (int i = 0; i < addDummyValues; i++) {
            characters.add(UUID.randomUUID().toString());
        }

        characters.add(addDummyValues / 2, character);

        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/characters")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONArray(characters).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }

    private void preparedGw2RestServerForCreateSubtoken(String gw2ApiToken, String gw2ApiSubtoken, Set<Gw2ApiPermission> requestPermissions, Instant expire) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/createsubtoken")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andExpect(queryParam("permissions", split(",", containingAll(requestPermissions.stream().map(Gw2ApiPermission::gw2).toArray(String[]::new)))))
                .andExpect(queryParam("expire", asInstant(instant(expire))))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of("subtoken", gw2ApiSubtoken)).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }

    private void preparedGw2RestServerForAccountRequest(UUID gw2AccountId, String gw2ApiToken) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of(
                            "id", gw2AccountId,
                            "name", "SomeName.4321"
                    )).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);

                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }
}