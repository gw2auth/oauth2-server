package com.gw2auth.oauth2.server.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import com.gw2auth.oauth2.server.util.Utils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.hamcrest.core.*;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static com.gw2auth.oauth2.server.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
public class OAuth2ServerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AccountService accountService;

    @Autowired
    private ClientRegistrationService clientRegistrationService;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @Test
    public void authorizationCodeRequestUnknownClient() throws Exception {
        this.mockMvc.perform(
                get("/oauth2/authorize")
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, "abcdefg")
                        .queryParam(OAuth2ParameterNames.SCOPE, Gw2ApiPermission.ACCOUNT.oauth2())
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, "http://127.0.0.1/")
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        ).andExpect(status().isBadRequest());
    }

    @Test
    public void authorizationCodeRequestNotLoggedIn() throws Exception {
        performAuthorizeWithNewClient(null)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new StringEndsWith("/login")));
    }

    @WithGw2AuthLogin
    public void authorizationCodeRequestConsent(MockHttpSession session) throws Exception {
        performAuthorizeWithNewClient(session, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.TRADINGPOST.oauth2()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2/consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.TRADINGPOST.oauth2())))
                        ))
                ))));
    }

    @WithGw2AuthLogin
    public void authorizationCodeRequestWithExistingConsent(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(session, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new AllOf<>(
                        new StringStartsWith(clientRegistration.redirectUri()),
                        asUri(new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, hasQueryParam(OAuth2ParameterNames.CODE)))
                )));
    }

    @WithGw2AuthLogin
    public void authorizationCodeRequestWithUpgradingConsent(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(session, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.INVENTORIES.oauth2()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2/consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.INVENTORIES.oauth2())))
                        ))
                ))));
    }

    @WithGw2AuthLogin
    public void authorizationCodeRequestWithExistingConsentAndConsentForce(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(session, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2()), true)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2/consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(Gw2ApiPermission.ACCOUNT.oauth2())))
                        ))
                ))));
    }

    @WithGw2AuthLogin
    public void consentSubmit(MockHttpSession session) throws Exception {
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(session, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();
        URI redirectUri = URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl()));

        // read request information from redirected uri
        final String[] clientId = new String[1];
        final String[] state = new String[1];
        final String[] scopes = new String[1];

        Utils.parseQuery(redirectUri.getRawQuery())
                .forEach((pair) -> {
                    switch (pair[0]) {
                        case OAuth2ParameterNames.CLIENT_ID -> clientId[0] = pair[1];
                        case OAuth2ParameterNames.STATE -> state[0] = pair[1];
                        case OAuth2ParameterNames.SCOPE -> scopes[0] = pair[1];
                    }
                });

        assertNotNull(clientId[0]);
        assertNotNull(state[0]);
        assertNotNull(scopes[0]);

        // insert some dummy api tokens
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, "GW2AccIdFirst", Instant.now(), "TokenA", Set.of(Gw2ApiPermission.ACCOUNT.gw2()), "First"));
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, "GW2AccIdSecond", Instant.now(), "TokenB", Set.of(Gw2ApiPermission.ACCOUNT.gw2()), "Second"));
        this.apiTokenRepository.save(new ApiTokenEntity(accountId, "GW2AccIdThird", Instant.now(), "TokenC", Set.of(), "Third"));

        // lookup the consent info (containing the submit uri and parameters that should be submitted)
        result = this.mockMvc.perform(
                get("/api/oauth2/consent")
                        .session(session)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId[0])
                        .queryParam(OAuth2ParameterNames.STATE, state[0])
                        .queryParam(OAuth2ParameterNames.SCOPE, scopes[0])
        ).andReturn();

        // read the consent info and build the submit request
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode consentInfo = mapper.readTree(result.getResponse().getContentAsString());
        final String submitUri = consentInfo.get("submitFormUri").textValue();

        MockHttpServletRequestBuilder builder = post(submitUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .session(session)
                .with(csrf());

        for (Map.Entry<String, JsonNode> entry : (Iterable<? extends Map.Entry<String, JsonNode>>) () -> consentInfo.get("submitFormParameters").fields()) {
            final String name = entry.getKey();
            final JsonNode values = entry.getValue();

            for (int i = 0; i < values.size(); i++) {
                builder = builder.param(name, values.get(i).textValue());
            }
        }

        final JsonNode apiTokensWithSufficientPermissions = consentInfo.get("apiTokensWithSufficientPermissions");

        assertEquals(2, apiTokensWithSufficientPermissions.size());
        assertEquals(1, consentInfo.get("apiTokensWithInsufficientPermissions").size());

        for (int i = 0; i < apiTokensWithSufficientPermissions.size(); i++) {
            builder = builder.param("token:" + apiTokensWithSufficientPermissions.get(i).get("gw2AccountId").textValue(), "");
        }

        // submit the consent
        result = this.mockMvc.perform(builder)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new AllOf<>(
                        new StringStartsWith(clientRegistration.redirectUri()),
                        asUri(new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, hasQueryParam(OAuth2ParameterNames.CODE)))
                )))
                .andReturn();

        // verify the authorization has been saved
        final ClientAuthorizationEntity clientAuthorizationEntity = this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientAuthorizationEntity);
        assertEquals(clientAuthorizationEntity.authorizedScopes(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2()));

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // get the code param from the redirect uri
        redirectUri = URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl()));
        final String codeParam = Utils.parseQuery(redirectUri.getRawQuery())
                .filter((pair) -> pair[0].equals(OAuth2ParameterNames.CODE))
                .map((pair) -> pair[1])
                .findFirst()
                .orElse(null);

        assertNotNull(codeParam);

        // prepare the mocked gw2 api server to respond with dummy JWTs
        final String dummySubtokenA = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUb2tlbkEiLCJpYXQiOjE2MzQwNzk3ODgsImV4cCI6MTYzNDA4MTU4NywicGVybWlzc2lvbnMiOlsiYWNjb3VudCJdfQ.RrSBgmEkacAjSdyEcKAyf5Zio5Vz98m2gMyxsr683fQ";
        final String dummySubtokenB = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUb2tlbkIiLCJpYXQiOjE2MzQwNzk3ODgsImV4cCI6MTYzNDA4MTU4NywicGVybWlzc2lvbnMiOlsiYWNjb3VudCJdfQ.O_aKd92J57twbv6Cnj_wLnlSgldOvLW3DR5316N-GKI";

        this.gw2RestServer.reset();
        this.gw2RestServer.expect(times(2), requestTo(new StringStartsWith("/v2/createsubtoken")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", new StringStartsWith("Bearer ")))
                .andExpect(queryParam("permissions", Gw2ApiPermission.ACCOUNT.gw2()))
                .andExpect(queryParam("expire", asInstant(instantWithinTolerance(Instant.now().plus(Duration.ofMinutes(30L)), Duration.ofSeconds(5L)))))
                .andRespond((request) -> {
                    final String gw2ApiToken = request.getHeaders().getFirst("Authorization").replaceFirst("Bearer ", "");

                    final String subtoken = switch (gw2ApiToken) {
                        case "TokenA" -> dummySubtokenA;
                        case "TokenB" -> dummySubtokenB;
                        default -> null;
                    };

                    if (subtoken == null) {
                        return new MockClientHttpResponse(new byte[0], HttpStatus.UNAUTHORIZED);
                    }

                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of("subtoken", subtoken)).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });

        // retrieve an access token
        // dont use the user session here!
        result = this.mockMvc.perform(
                post("/oauth2/token")
                        .queryParam(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .queryParam(OAuth2ParameterNames.CODE, codeParam)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId())
                        .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, clientRegistration.redirectUri())
        )
                .andExpect(expectValidTokenResponse())
                .andReturn();

        // verify the authorized tokens have been updated
        clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        final Set<String> savedSubtokens = clientAuthorizationTokenEntities.stream()
                .map(ClientAuthorizationTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertTrue(savedSubtokens.contains(dummySubtokenA));
        assertTrue(savedSubtokens.contains(dummySubtokenB));

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                "GW2AccIdFirst", new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                "GW2AccIdSecond", new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();

        // dont use the user session here!
        result = this.mockMvc.perform(
                post("/oauth2/token")
                        .queryParam(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
                        .queryParam(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId())
                        .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
        )
                .andExpect(expectValidTokenResponse())
                .andReturn();

        tokenResponse = assertTokenResponse(result, () -> Map.of(
                "GW2AccIdFirst", new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                "GW2AccIdSecond", new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));
    }

    private JsonNode assertTokenResponse(MvcResult result, Supplier<Map<String, com.nimbusds.jose.shaded.json.JSONObject>> expectedTokenSupplier) throws Exception {
        final JsonNode tokenResponse = new ObjectMapper().readTree(result.getResponse().getContentAsString());
        final JWT accessToken = JWTParser.parse(tokenResponse.get("access_token").textValue());

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.gw2()), new HashSet<>(accessToken.getJWTClaimsSet().getStringListClaim("gw2:permissions")));

        final Map<String, com.nimbusds.jose.shaded.json.JSONObject> expectedTokens = new HashMap<>(expectedTokenSupplier.get());

        for (Map.Entry<String, Object> entry : accessToken.getJWTClaimsSet().getJSONObjectClaim("gw2:tokens").entrySet()) {
            final String gw2AccountId = entry.getKey();
            final com.nimbusds.jose.shaded.json.JSONObject token = (com.nimbusds.jose.shaded.json.JSONObject) entry.getValue();
            final com.nimbusds.jose.shaded.json.JSONObject expectedToken = expectedTokens.remove(gw2AccountId);

            assertNotNull(expectedToken);
            assertEquals(expectedToken, token);
        }

        assertTrue(expectedTokens.isEmpty());

        return tokenResponse;
    }

    private ResultMatcher expectValidTokenResponse() {
        return ResultMatcher.matchAll(
                status().isOk(),
                jsonPath("$.refresh_token").value(new IsAnything<>()),
                jsonPath("$.access_token").value(new IsAnything<>()),
                jsonPath("$.token_type").value("Bearer"),
                jsonPath("$.scope").value(Gw2ApiPermission.ACCOUNT.oauth2()),
                jsonPath("$.expires_in").value(new IsAnything<>())
        );
    }

    private ResultActions performAuthorizeWithNewClient(MockHttpSession session) throws Exception {
        return performAuthorizeWithNewClient(session, List.of(Gw2ApiPermission.ACCOUNT.oauth2()));
    }

    private ResultActions performAuthorizeWithNewClient(MockHttpSession session, List<String> scopes) throws Exception {
        return performAuthorizeWithClient(session, createClientRegistration().clientRegistration(), scopes, false);
    }

    private ResultActions performAuthorizeWithClient(MockHttpSession session, ClientRegistration clientRegistration, List<String> scopes) throws Exception {
        return performAuthorizeWithClient(session, clientRegistration, scopes, false);
    }

    private ResultActions performAuthorizeWithClient(MockHttpSession session, ClientRegistration clientRegistration, List<String> scopes, boolean force) throws Exception {
        MockHttpServletRequestBuilder builder = get("/oauth2/authorize");

        if (session != null) {
            builder = builder.session(session);
        }

        if (force) {
            builder = builder.queryParam("consent", "force");
        }

        return this.mockMvc.perform(
                builder
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientId())
                        .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", scopes))
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, clientRegistration.redirectUri())
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        );
    }

    private ClientRegistrationCreation createClientRegistration() {
        final Account account = this.accountService.getOrCreateAccount(UUID.randomUUID().toString(), UUID.randomUUID().toString());
        return this.clientRegistrationService.createClientRegistration(account.id(), "Test", Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()), "https://clientapplication.gw2auth.com/callback");
    }
}
