package com.gw2auth.oauth2.server.web.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.util.Pair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
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
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Matchers.containingAll;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class ApiTokenControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private ApplicationClientAccountRepository applicationClientAccountRepository;

    @Autowired
    private ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TestHelper testHelper;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @Test
    public void getApiTokensUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/token"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getApiTokens(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> apiTokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> apiTokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Set.of(Gw2ApiPermission.TRADINGPOST), "TokenB");
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> apiTokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Set.of(Gw2ApiPermission.BUILDS, Gw2ApiPermission.PROGRESSION), "TokenC");

        this.testHelper.createAccountVerification(accountId, apiTokenB.v1().gw2AccountId());

        final ApplicationClientEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "ClientA");
        final ApplicationClientEntity clientRegistrationB = this.testHelper.createClientRegistration(accountId, "ClientB");

        final ApplicationClientAccountEntity clientConsentA = this.testHelper.createClientConsent(accountId, clientRegistrationA.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));
        final ApplicationClientAccountEntity clientConsentB = this.testHelper.createClientConsent(accountId, clientRegistrationB.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));

        final String authorizationIdA = this.testHelper.createClientAuthorization(accountId, clientConsentA).id();
        final String authorizationIdB = this.testHelper.createClientAuthorization(accountId, clientConsentB).id();

        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdA, apiTokenB.v1().gw2AccountId(), apiTokenC.v1().gw2AccountId());
        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdB, apiTokenC.v1().gw2AccountId());

        final String responseJson = this.mockMvc.perform(get("/api/token").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("3"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode responseNode = mapper.readTree(responseJson);
        assertTrue(responseNode.isArray());

        final Map<UUID, ExpectedApiToken> expectedApiTokens = new HashMap<>(Map.of(
                apiTokenA.v1().gw2AccountId(), new ExpectedApiToken(apiTokenA, false, List.of()),
                apiTokenB.v1().gw2AccountId(), new ExpectedApiToken(apiTokenB, true, List.of(clientRegistrationA)),
                apiTokenC.v1().gw2AccountId(), new ExpectedApiToken(apiTokenC, false, List.of(clientRegistrationA, clientRegistrationB))
        ));

        Instant previousCreationTime = Instant.MIN;

        for (int i = 0; i < responseNode.size(); i++) {
            final JsonNode tokenNode = responseNode.get(i);
            final UUID gw2AccountId = UUID.fromString(tokenNode.get("gw2AccountId").textValue());
            final ExpectedApiToken expectedApiToken = expectedApiTokens.remove(gw2AccountId);

            assertExpectedApiToken(expectedApiToken, tokenNode);

            final Instant creationTime = Instant.parse(tokenNode.get("creationTime").textValue());
            assertTrue(previousCreationTime.isBefore(creationTime));
            previousCreationTime = creationTime;
        }

        assertTrue(expectedApiTokens.isEmpty());
    }

    @Test
    public void addApiTokenUnauthenticated() throws Exception {
        this.mockMvc.perform(post("/api/token").with(csrf()).content(UUID.randomUUID().toString()))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenInvalid(SessionHandle sessionHandle) throws Exception {
        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        preparedGw2RestServerInvalidRequest("/v2/tokeninfo", gw2ApiToken);
        preparedGw2RestServerInvalidRequest("/v2/account", gw2ApiToken);

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenInvalidRootTokenFormat(SessionHandle sessionHandle) throws Exception {
        final String gw2ApiToken = TestHelper.randomRootToken() + "Hello";

        // dont expect any request to the gw2 api
        this.gw2RestServer.reset();

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenInvalidSubTokenFormat(SessionHandle sessionHandle) throws Exception {
        final String gw2ApiToken = new PlainJWT(new JWTClaimsSet.Builder().build()).serialize();

        // dont expect any request to the gw2 api
        this.gw2RestServer.reset();

        this.mockMvc.perform(
                        post("/api/token")
                                .with(sessionHandle)
                                .with(csrf())
                                .content(gw2ApiToken)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenAlreadyAdded(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow(), gw2AccountId, Set.of(), "Name");

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenLinkedToOtherAccountButNotVerified(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();

        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Some Name");

        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId.toString()))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value("Gw2AccountName.1234"))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.WALLET.gw2())))
                .andExpect(jsonPath("$.isVerified").value("false"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow(), gw2AccountId).isPresent());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenLinkedAndVerifiedToOtherAccount(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();

        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Some Name");
        this.testHelper.createAccountVerification(otherUserAccountId, gw2AccountId);

        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isNotAcceptable());

        assertTrue(this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow(), gw2AccountId).isEmpty());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiTokenAlreadyVerified(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        final Gw2AccountEntity gw2AccountEntity = this.testHelper.getOrCreateGw2Account(accountId, gw2AccountId);
        this.testHelper.createAccountVerification(accountId, gw2AccountId);

        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId.toString()))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value(gw2AccountEntity.displayName()))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.TRADINGPOST.gw2())))
                .andExpect(jsonPath("$.isVerified").value("true"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).isPresent());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addApiToken(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .with(sessionHandle)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId.toString()))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value("Gw2AccountName.1234"))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.WALLET.gw2())))
                .andExpect(jsonPath("$.isVerified").value("false"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.gw2AccountApiTokenRepository.findByAccountIdAndGw2AccountId(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow(), gw2AccountId).isPresent());
    }

    @Test
    public void updateApiTokenUnauthenticated() throws Exception {
        final String gw2AccountId = UUID.randomUUID().toString();

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(csrf())
                        .queryParam("gw2ApiToken", UUID.randomUUID().toString())
        )
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiTokenThatHasBeenVerifiedByAnotherAccount(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final UUID gw2AccountId = UUID.randomUUID();

        // save key for the same gw2 account id on both accounts
        this.testHelper.createApiToken(accountId, gw2AccountId, Set.of(), "Name A");
        this.testHelper.createApiToken(otherUserAccountId, gw2AccountId, Set.of(), "Name B");

        // save verification for the other account
        this.testHelper.createAccountVerification(otherUserAccountId, gw2AccountId);

        // prepare the gw2 rest server
        final String gw2ApiToken = TestHelper.randomRootToken();

        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "TokenA", Set.of(Gw2ApiPermission.ACCOUNT));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andExpect(status().isNotAcceptable());

        // api token should be deleted now
        assertTrue(this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(gw2AccountId)).isEmpty());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiTokenNotExisting(SessionHandle sessionHandle) throws Exception {
        final UUID gw2AccountId = UUID.randomUUID();
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiTokenInvalid(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(accountId, gw2AccountId, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        preparedGw2RestServerInvalidRequest("/v2/tokeninfo", gw2ApiToken);
        preparedGw2RestServerInvalidRequest("/v2/account", gw2ApiToken);

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiTokenWithoutAccountPermission(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(accountId, gw2AccountId, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiTokenForDifferentGw2AccountId(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountIdOriginal = UUID.randomUUID();
        this.testHelper.createApiToken(accountId, gw2AccountIdOriginal, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");

        final UUID gw2AccountIdUpdate = UUID.randomUUID();
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT));
        preparedGw2RestServerForAccountRequest(gw2AccountIdUpdate, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountIdOriginal)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void updateApiToken(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> gw2AccountWithApiToken = this.testHelper.createApiToken(accountId, gw2AccountId, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");

        // verified
        this.testHelper.createAccountVerification(accountId, gw2AccountId);

        // register 2 clients
        final ApplicationClientEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "ClientA");
        final ApplicationClientEntity clientRegistrationB = this.testHelper.createClientRegistration(accountId, "ClientB");

        // authorize 2 clients
        final ApplicationClientAccountEntity clientConsentA = this.testHelper.createClientConsent(accountId, clientRegistrationA.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));
        final ApplicationClientAccountEntity clientConsentB = this.testHelper.createClientConsent(accountId, clientRegistrationB.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));

        final String authorizationIdA = this.testHelper.createClientAuthorization(accountId, clientConsentA).id();
        final String authorizationIdB = this.testHelper.createClientAuthorization(accountId, clientConsentB).id();

        // use this token in both clients
        this.testHelper.createClientAuthorizationToken(accountId, authorizationIdA, gw2AccountId);
        this.testHelper.createClientAuthorizationToken(accountId, authorizationIdB, gw2AccountId);

        final String gw2ApiToken = TestHelper.randomRootToken();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        final String responseJson = this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .with(sessionHandle)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
                        .queryParam("displayName", "New Display Name")
        )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode apiTokenNode = mapper.readTree(responseJson);

        assertExpectedApiToken(
                new ExpectedApiToken(gw2AccountWithApiToken, true, List.of(clientRegistrationA, clientRegistrationB)),
                "New Display Name",// display name should be updated
                gw2ApiToken,// api token should be updated
                Set.of(Gw2ApiPermission.ACCOUNT.gw2()),// the new api token has less permissions than the original one
                apiTokenNode
        );
    }

    @Test
    public void deleteApiTokenUnauthorized() throws Exception {
        this.mockMvc.perform(delete("/api/token/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteApiTokenNotExisting(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(delete("/api/token/{gw2AccountId}", UUID.randomUUID()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteApiToken(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final UUID gw2AccountId = UUID.randomUUID();
        this.testHelper.createApiToken(accountId, gw2AccountId, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.GUILDS), "TokenA");

        // verified
        this.testHelper.createAccountVerification(accountId, gw2AccountId);

        // register a client
        final ApplicationClientEntity clientRegistration = this.testHelper.createClientRegistration(accountId, "ClientA");

        // authorize the client
        final ApplicationClientAccountEntity clientConsent = this.testHelper.createClientConsent(accountId, clientRegistration.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));

        final String authorizationId = this.testHelper.createClientAuthorization(accountId, clientConsent).id();

        // use this token to the authorization
        this.testHelper.createClientAuthorizationToken(accountId, authorizationId, gw2AccountId);

        this.mockMvc.perform(delete("/api/token/{gw2AccountId}", gw2AccountId).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // the token should be deleted
        assertTrue(this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(gw2AccountId)).isEmpty());

        // the verification should still be there
        assertTrue(this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).isPresent());

        // the token should still be in the authorization
        assertFalse(this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(authorizationId, accountId).isEmpty());

        // the authorization should still be there
        assertTrue(this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(clientConsent.applicationClientId(), accountId).isPresent());
    }

    private void preparedGw2RestServerForAccountRequest(UUID gw2AccountId, String gw2ApiToken, String accountName) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> {
                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of(
                            "id", gw2AccountId,
                            "name", accountName
                    )).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);

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

    private void preparedGw2RestServerInvalidRequest(String url, String gw2ApiToken) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith(url)))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", "Bearer " + gw2ApiToken))
                .andRespond((request) -> new MockClientHttpResponse(new byte[0], HttpStatus.UNAUTHORIZED));
    }

    private void assertExpectedApiToken(ExpectedApiToken expectedApiToken, JsonNode apiTokenNode) {
        assertExpectedApiToken(
                expectedApiToken,
                expectedApiToken.gw2AccountWithApiToken().v1().displayName(),
                expectedApiToken.gw2AccountWithApiToken().v2().gw2ApiToken(),
                Gw2ApiPermission.fromBitSet(expectedApiToken.gw2AccountWithApiToken().v2().gw2ApiPermissionsBitSet())
                        .stream()
                        .map(Gw2ApiPermission::gw2).collect(Collectors.toUnmodifiableSet()),
                apiTokenNode
        );
    }

    private void assertExpectedApiToken(ExpectedApiToken expectedApiToken, String expectedDisplayName, String expectedGw2ApiToken, Set<String> expectedGw2ApiPermissions, JsonNode apiTokenNode) {
        assertNotNull(expectedApiToken);
        assertEquals(expectedApiToken.gw2AccountWithApiToken().v1().gw2AccountId(), UUID.fromString(apiTokenNode.get("gw2AccountId").textValue()));
        assertInstantEquals(expectedApiToken.gw2AccountWithApiToken().v2().creationTime(), apiTokenNode.get("creationTime").textValue());
        assertEquals(expectedGw2ApiToken, apiTokenNode.get("gw2ApiToken").textValue());
        assertEquals(expectedDisplayName, apiTokenNode.get("displayName").textValue());
        assertTrue(apiTokenNode.get("isValid").booleanValue());
        assertEquals(expectedApiToken.isVerified(), apiTokenNode.get("isVerified").booleanValue());

        // gw2 api permissions
        expectedGw2ApiPermissions = new HashSet<>(expectedGw2ApiPermissions);
        final JsonNode gw2ApiPermissionsNode = apiTokenNode.get("gw2ApiPermissions");
        assertTrue(gw2ApiPermissionsNode.isArray());

        for (int j = 0; j < gw2ApiPermissionsNode.size(); j++) {
            if (!expectedGw2ApiPermissions.remove(gw2ApiPermissionsNode.get(j).textValue())) {
                fail("Received unexpected gw2ApiPermission");
            }
        }

        assertTrue(expectedGw2ApiPermissions.isEmpty());

        // authorizations
        final Map<UUID, ApplicationClientEntity> expectedAuthorizations = expectedApiToken.authorizations().stream()
                .collect(Collectors.toMap(ApplicationClientEntity::id, Function.identity()));

        final JsonNode authorizationsNode = apiTokenNode.get("authorizations");
        assertTrue(authorizationsNode.isArray());

        for (int j = 0; j < authorizationsNode.size(); j++) {
            final JsonNode authorizationNode = authorizationsNode.get(j);
            final UUID clientId = UUID.fromString(authorizationNode.get("clientId").textValue());
            final ApplicationClientEntity expectedAuthorization = expectedAuthorizations.remove(clientId);

            assertNotNull(expectedAuthorization);
            assertEquals(expectedAuthorization.displayName(), authorizationNode.get("displayName").textValue());
        }

        assertTrue(expectedAuthorizations.isEmpty());
    }

    private record ExpectedApiToken(Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> gw2AccountWithApiToken, boolean isVerified, List<ApplicationClientEntity> authorizations) {}
}