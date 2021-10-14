package com.gw2auth.oauth2.server.web.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONObject;
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
import org.springframework.mock.web.MockHttpSession;
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
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @Test
    public void getApiTokensUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/token"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getApiTokens(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final ApiTokenEntity apiTokenA = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));
        final ApiTokenEntity apiTokenB = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.TRADINGPOST.gw2()), "TokenB"));
        final ApiTokenEntity apiTokenC = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.BUILDS.gw2(), Gw2ApiPermission.PROGRESSION.gw2()), "TokenC"));

        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(apiTokenB.gw2AccountId(), accountId));

        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "ClientA", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/a"));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "ClientB", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/b"));

        final ClientAuthorizationEntity clientAuthorizationA = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationA.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));
        final ClientAuthorizationEntity clientAuthorizationB = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationB.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));

        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenB.gw2AccountId(), "", Instant.now()));
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenC.gw2AccountId(), "", Instant.now()));

        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationB.clientRegistrationId(), apiTokenC.gw2AccountId(), "", Instant.now()));

        final String responseJson = this.mockMvc.perform(get("/api/token").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("3"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode responseNode = mapper.readTree(responseJson);
        assertTrue(responseNode.isArray());

        final Map<String, ExpectedApiToken> expectedApiTokens = new HashMap<>(Map.of(
                apiTokenA.gw2AccountId(), new ExpectedApiToken(apiTokenA, false, List.of()),
                apiTokenB.gw2AccountId(), new ExpectedApiToken(apiTokenB, true, List.of(clientRegistrationA)),
                apiTokenC.gw2AccountId(), new ExpectedApiToken(apiTokenC, false, List.of(clientRegistrationA, clientRegistrationB))
        ));

        for (int i = 0; i < responseNode.size(); i++) {
            final JsonNode tokenNode = responseNode.get(i);
            final String gw2AccountId = tokenNode.get("gw2AccountId").textValue();
            final ExpectedApiToken expectedApiToken = expectedApiTokens.remove(gw2AccountId);

            assertExpectedApiToken(expectedApiToken, tokenNode);
        }

        assertTrue(expectedApiTokens.isEmpty());
    }

    @Test
    public void addApiTokenUnauthenticated() throws Exception {
        this.mockMvc.perform(post("/api/token").with(csrf()).content(UUID.randomUUID().toString()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void addApiTokenInvalid(MockHttpSession session) throws Exception {
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        preparedGw2RestServerInvalidRequest("/v2/tokeninfo", gw2ApiToken);
        preparedGw2RestServerInvalidRequest("/v2/account", gw2ApiToken);

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void addApiTokenAlreadyAdded(MockHttpSession session) throws Exception {
        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(AuthenticationHelper.getUser(session).orElseThrow().getAccountId(), gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(), "Name"));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void addApiTokenLinkedToOtherAccountButNotVerified(MockHttpSession session) throws Exception {
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();

        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(otherUserAccountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(), "Some Name"));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value("Gw2AccountName.1234"))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.WALLET.gw2())))
                .andExpect(jsonPath("$.isVerified").value("false"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(AuthenticationHelper.getUser(session).orElseThrow().getAccountId(), gw2AccountId).isPresent());
    }

    @WithGw2AuthLogin
    public void addApiTokenLinkedAndVerifiedToOtherAccount(MockHttpSession session) throws Exception {
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();

        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(otherUserAccountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(), "Some Name"));
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, otherUserAccountId));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isNotAcceptable());

        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(AuthenticationHelper.getUser(session).orElseThrow().getAccountId(), gw2AccountId).isEmpty());
    }

    @WithGw2AuthLogin
    public void addApiTokenAlreadyVerified(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountId = UUID.randomUUID().toString();
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value("Gw2AccountName.1234"))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.TRADINGPOST.gw2())))
                .andExpect(jsonPath("$.isVerified").value("true"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).isPresent());
    }

    @WithGw2AuthLogin
    public void addApiToken(MockHttpSession session) throws Exception {
        final String gw2AccountId = UUID.randomUUID().toString();
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                post("/api/token")
                        .session(session)
                        .with(csrf())
                        .content(gw2ApiToken)
        )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gw2AccountId").value(gw2AccountId))
                .andExpect(jsonPath("$.creationTime").isString())
                .andExpect(jsonPath("$.gw2ApiToken").value(gw2ApiToken))
                .andExpect(jsonPath("$.displayName").value("Gw2AccountName.1234"))
                .andExpect(jsonPath("$.gw2ApiPermissions.length()").value("2"))
                .andExpect(jsonPath("$.gw2ApiPermissions[*]").value(containingAll(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.WALLET.gw2())))
                .andExpect(jsonPath("$.isVerified").value("false"))
                .andExpect(jsonPath("$.authorizations.length()").value("0"));

        assertTrue(this.apiTokenRepository.findByAccountIdAndGw2AccountId(AuthenticationHelper.getUser(session).orElseThrow().getAccountId(), gw2AccountId).isPresent());
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

    @WithGw2AuthLogin
    public void updateApiTokenThatHasBeenVerifiedByAnotherAccount(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();
        final String gw2AccountId = UUID.randomUUID().toString();

        // save key for the same gw2 account id on both accounts
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(), "Name A"));
        this.apiTokenRepository.save(new ApiTokenEntity(otherUserAccountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(), "Name B"));

        // save verification for the other account
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, otherUserAccountId));

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .session(session)
                        .with(csrf())
                        .queryParam("displayName", "Hello World")
        )
                .andExpect(status().isNotAcceptable());

        // api token should be deleted now
        assertTrue(this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(gw2AccountId)).isEmpty());
    }

    @WithGw2AuthLogin
    public void updateApiTokenNotExisting(MockHttpSession session) throws Exception {
        final String gw2AccountId = UUID.randomUUID().toString();
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .session(session)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void updateApiTokenInvalid(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        preparedGw2RestServerInvalidRequest("/v2/tokeninfo", gw2ApiToken);
        preparedGw2RestServerInvalidRequest("/v2/account", gw2ApiToken);

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .session(session)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void updateApiTokenWithoutAccountPermission(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.WALLET));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .session(session)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void updateApiTokenForDifferentGw2AccountId(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountIdOriginal = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountIdOriginal, Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));

        final String gw2AccountIdUpdate = UUID.randomUUID().toString();
        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT));
        preparedGw2RestServerForAccountRequest(gw2AccountIdUpdate, gw2ApiToken, "Gw2AccountName.1234");

        this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountIdOriginal)
                        .session(session)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
        )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void updateApiToken(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountId = UUID.randomUUID().toString();
        final ApiTokenEntity apiToken = this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));

        // verified
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));

        // register 2 clients
        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "ClientA", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/a"));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "ClientB", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/b"));

        // authorize 2 clients
        final ClientAuthorizationEntity clientAuthorizationA = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationA.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));
        final ClientAuthorizationEntity clientAuthorizationB = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationB.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));

        // use this token in both clients
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), gw2AccountId, "", Instant.now()));
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationB.clientRegistrationId(), gw2AccountId, "", Instant.now()));

        final String gw2ApiToken = UUID.randomUUID().toString();

        // prepare the gw2 rest server
        this.gw2RestServer.reset();
        prepareGw2RestServerForTokenInfoRequest(gw2ApiToken, "Token Name", Set.of(Gw2ApiPermission.ACCOUNT));
        preparedGw2RestServerForAccountRequest(gw2AccountId, gw2ApiToken, "Gw2AccountName.1234");

        final String responseJson = this.mockMvc.perform(
                patch("/api/token/{gw2AccountId}", gw2AccountId)
                        .session(session)
                        .with(csrf())
                        .queryParam("gw2ApiToken", gw2ApiToken)
                        .queryParam("displayName", "New Display Name")
        )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode apiTokenNode = mapper.readTree(responseJson);

        assertExpectedApiToken(
                new ExpectedApiToken(apiToken, true, List.of(clientRegistrationA, clientRegistrationB)),
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

    @WithGw2AuthLogin
    public void deleteApiTokenNotExisting(MockHttpSession session) throws Exception {
        this.mockMvc.perform(delete("/api/token/someid").session(session).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void deleteApiToken(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final String gw2AccountId = UUID.randomUUID().toString();
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, gw2AccountId, Instant.now(), UUID.randomUUID().toString(), Set.of(Gw2ApiPermission.ACCOUNT.gw2(), Gw2ApiPermission.GUILDS.gw2()), "TokenA"));

        // verified
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));

        // register a client
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "ClientA", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/a"));

        // authorize the client
        final ClientAuthorizationEntity clientAuthorization = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistration.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));

        // use this token to the authorization
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorization.clientRegistrationId(), gw2AccountId, "", Instant.now()));

        this.mockMvc.perform(delete("/api/token/{gw2AccountId}", gw2AccountId).session(session).with(csrf()))
                .andExpect(status().isOk());

        // the token should be deleted
        assertTrue(this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(gw2AccountId)).isEmpty());

        // the verification should still be there
        assertTrue(this.gw2AccountVerificationRepository.findById(gw2AccountId).isPresent());

        // the token should no longer be in the authorization
        assertTrue(this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientAuthorization.clientRegistrationId()).isEmpty());

        // the authorization should still be there
        assertTrue(this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientAuthorization.clientRegistrationId()).isPresent());
    }

    private void preparedGw2RestServerForAccountRequest(String gw2AccountId, String gw2ApiToken, String accountName) {
        this.gw2RestServer.expect(requestTo(new StringStartsWith("/v2/account")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", new IsEqual<>("Bearer " + gw2ApiToken)))
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
                .andExpect(MockRestRequestMatchers.header("Authorization", new IsEqual<>("Bearer " + gw2ApiToken)))
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
                .andExpect(MockRestRequestMatchers.header("Authorization", new IsEqual<>("Bearer " + gw2ApiToken)))
                .andRespond((request) -> new MockClientHttpResponse(new byte[0], HttpStatus.UNAUTHORIZED));
    }

    private void assertExpectedApiToken(ExpectedApiToken expectedApiToken, JsonNode apiTokenNode) {
        assertExpectedApiToken(expectedApiToken, expectedApiToken.apiToken().displayName(), expectedApiToken.apiToken().gw2ApiToken(), expectedApiToken.apiToken().gw2ApiPermissions(), apiTokenNode);
    }

    private void assertExpectedApiToken(ExpectedApiToken expectedApiToken, String expectedDisplayName, String expectedGw2ApiToken, Set<String> expectedGw2ApiPermissions, JsonNode apiTokenNode) {
        assertNotNull(expectedApiToken);
        assertEquals(expectedApiToken.apiToken().gw2AccountId(), apiTokenNode.get("gw2AccountId").textValue());
        assertInstantEquals(expectedApiToken.apiToken().creationTime(), apiTokenNode.get("creationTime").textValue());
        assertEquals(expectedGw2ApiToken, apiTokenNode.get("gw2ApiToken").textValue());
        assertEquals(expectedDisplayName, apiTokenNode.get("displayName").textValue());
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
        final Map<String, ClientRegistrationEntity> expectedAuthorizations = expectedApiToken.authorizations().stream()
                .collect(Collectors.toMap(ClientRegistrationEntity::clientId, Function.identity()));

        final JsonNode authorizationsNode = apiTokenNode.get("authorizations");
        assertTrue(authorizationsNode.isArray());

        for (int j = 0; j < authorizationsNode.size(); j++) {
            final JsonNode authorizationNode = authorizationsNode.get(j);
            final String clientId = authorizationNode.get("clientId").textValue();
            final ClientRegistrationEntity expectedAuthorization = expectedAuthorizations.remove(clientId);

            assertNotNull(expectedAuthorization);
            assertEquals(expectedAuthorization.displayName(), authorizationNode.get("displayName").textValue());
        }

        assertTrue(expectedAuthorizations.isEmpty());
    }

    private record ExpectedApiToken(ApiTokenEntity apiToken, boolean isVerified, List<ClientRegistrationEntity> authorizations) {}
}