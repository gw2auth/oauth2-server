package com.gw2auth.oauth2.server.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.apisubtoken.ApiSubTokenEntity;
import com.gw2auth.oauth2.server.repository.apisubtoken.ApiSubTokenRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.OAuth2TokenCustomizerService;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationServiceImpl;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.util.QueryParam;
import com.gw2auth.oauth2.server.util.Utils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.hamcrest.core.AllOf;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.StringEndsWith;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenType;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Matchers.*;
import static com.gw2auth.oauth2.server.service.client.consent.ClientConsentService.GW2AUTH_VERIFIED_SCOPE;
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
    private ClientConsentRepository clientConsentRepository;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private OAuth2TokenCustomizerService oAuth2TokenCustomizerService;

    @Autowired
    private ApiSubTokenRepository apiSubTokenRepository;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

    @Autowired
    private ClientAuthorizationServiceImpl clientAuthorizationService;

    @Autowired
    private TestHelper testHelper;
    
    private UUID gw2AccountId1st;
    private UUID gw2AccountId2nd;
    private UUID gw2AccountId3rd;
    
    @BeforeEach
    public void init() {
        this.gw2AccountId1st = UUID.randomUUID();
        this.gw2AccountId2nd = UUID.randomUUID();
        this.gw2AccountId3rd = UUID.randomUUID();
    }

    @AfterEach
    public void resetClock() {
        this.clientAuthorizationService.setClock(Clock.systemUTC());
        this.oAuth2TokenCustomizerService.setClock(Clock.systemUTC());
    }

    @Test
    public void oidcConfigurationIsNotAccessible() throws Exception {
        this.mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void oidcLoginIsNotAccessible() throws Exception {
        this.mockMvc.perform(get("/connect/register"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void oidcUserinfoIsNotAccessible() throws Exception {
        this.mockMvc.perform(get("/userinfo"))
                .andExpect(status().isNotFound());
    }

    @Test
    public void oauth2Configuration() throws Exception {
        this.mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").isString())
                .andExpect(jsonPath("$.authorization_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/authorize")))
                .andExpect(jsonPath("$.token_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/token")))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt")))
                .andExpect(jsonPath("$.jwks_uri").value(org.hamcrest.Matchers.endsWith("/oauth2/jwks")))
                .andExpect(jsonPath("$.response_types_supported").value(containingAll("code")))
                .andExpect(jsonPath("$.grant_types_supported").value(containingAll("authorization_code","client_credentials","refresh_token")))
                .andExpect(jsonPath("$.revocation_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/revoke")))
                .andExpect(jsonPath("$.revocation_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt")))
                .andExpect(jsonPath("$.introspection_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/introspect")))
                .andExpect(jsonPath("$.introspection_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt")))
                .andExpect(jsonPath("$.code_challenge_methods_supported").value(containingAll("S256")))
                // oidc not expected
                .andExpect(jsonPath("$.subject_types_supported").doesNotExist())
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported").doesNotExist())
                .andExpect(jsonPath("$.scopes_supported").doesNotExist());
    }

    @Test
    public void authorizationCodeRequestUnknownClient() throws Exception {
        this.mockMvc.perform(
                get("/oauth2/authorize")
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, UUID.randomUUID().toString())
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
    public void authorizationCodeRequestConsent(CookieHolder cookieHolder) throws Exception {
        performAuthorizeWithNewClient(cookieHolder, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.TRADINGPOST.oauth2()))
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
    public void authorizationCodeRequestWithExistingConsentButWithoutAPITokens(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientConsentRepository.save(new ClientConsentEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2()))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2/consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.SCOPE),
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE)
                        ))
                ))));
    }

    @WithGw2AuthLogin
    public void authorizationCodeRequestWithUpgradingConsent(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientConsentRepository.save(new ClientConsentEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.INVENTORIES.oauth2()))
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
    public void authorizationCodeRequestWithExistingConsentAndPromptConsent(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistration clientRegistration = createClientRegistration().clientRegistration();

        this.clientConsentRepository.save(new ClientConsentEntity(
                accountId,
                clientRegistration.id(),
                UUID.randomUUID(),
                Set.of(Gw2ApiPermission.ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2()), true)
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
    public void consentSubmitAndHappyFlow(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        // verify the tokens have been saved
        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the subtokens have been saved
        final Set<String> subTokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, subTokens.size());
        assertTrue(subTokens.contains(dummySubtokenA));
        assertTrue(subTokens.contains(dummySubtokenB));

        // verify the validity status has been saved
        final List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(clientRegistrationCreation, refreshToken).andReturn();

        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @WithGw2AuthLogin
    public void consentSubmitWithExpiredSubtokens(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the subtokens have been updated
        clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        Set<String> savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ));

        // prepare the gw2 reset api for new subtoken requests
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        dummySubtokenB[0] = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        prepareGw2RestServerForCreateSubToken(Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]));

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(clientRegistrationCreation, refreshToken).andReturn();

        // verify the subtokens have been updated
        savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the new response
        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @WithGw2AuthLogin
    public void consentSubmitWithSubtokenRetrievalError(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the subtokens been updated
        Set<String> savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ));

        // prepare the gw2 reset api for new subtoken requests (dont return a new subtoken for TokenB in this testcase)
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        prepareGw2RestServerForCreateSubToken(Map.of(tokenA, dummySubtokenA[0], tokenB, ""));

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(clientRegistrationCreation, refreshToken).andReturn();

        // verify the subtokens have been updated, but only for one
        savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved, but only for the first one
        apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());

        for (ApiTokenEntity apiTokenEntity : apiTokenEntities) {
            if (apiTokenEntity.gw2AccountId().equals(this.gw2AccountId1st)) {
                assertTrue(apiTokenEntity.isValid());
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidCheckTime());
            } else {
                assertTrue(apiTokenEntity.isValid());
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidCheckTime()));
            }
        }

        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "error", "Failed to obtain new subtoken"))
        ));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @WithGw2AuthLogin
    public void consentSubmitWithUnexpectedGW2APIException(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // prepare the gw2 api for the next requests
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        this.gw2RestServer.reset();
        this.gw2RestServer.expect(times(2), requestTo(new StringStartsWith("/v2/createsubtoken")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", new StringStartsWith("Bearer ")))
                .andExpect(queryParam("permissions", split(",", containingAll(Gw2ApiPermission.ACCOUNT.gw2()))))
                .andExpect(queryParam("expire", asInstant(instantWithinTolerance(Instant.now().plus(Duration.ofMinutes(30L)), Duration.ofSeconds(5L)))))
                .andRespond((request) -> {
                    final String gw2ApiToken = request.getHeaders().getFirst("Authorization").replaceFirst("Bearer ", "");
                    final String subtoken;

                    if (gw2ApiToken.equals(tokenA)) {
                        subtoken = dummySubtokenA;
                    } else if (gw2ApiToken.equals(tokenB)) {
                        throw new RuntimeException("unexpected exception");
                    } else {
                        subtoken = null;
                    }

                    if (subtoken == null || subtoken.isEmpty()) {
                        return new MockClientHttpResponse(new byte[0], HttpStatus.UNAUTHORIZED);
                    }

                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of("subtoken", subtoken)).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });

        // retrieve the initial access and refresh token
        final String codeParam = Utils.parseQuery(URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())).getRawQuery())
                .filter(QueryParam::hasValue)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.CODE))
                .map(QueryParam::value)
                .findFirst()
                .orElse(null);

        assertNotNull(codeParam);

        // retrieve an access token
        // dont use the user session here!
        result = this.mockMvc.perform(
                post("/oauth2/token")
                        .queryParam(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .queryParam(OAuth2ParameterNames.CODE, codeParam)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                        .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, TestHelper.first(clientRegistrationCreation.clientRegistration().redirectUris()).orElseThrow())
        )
                .andExpectAll(expectValidTokenResponse())
                .andReturn();

        // verify the subtokens have been updated
        final Set<String> savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(1, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA));

        // verify the validity status has been saved
        final List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());

        for (ApiTokenEntity apiTokenEntity : apiTokenEntities) {
            if (apiTokenEntity.gw2AccountId().equals(this.gw2AccountId1st)) {
                assertTrue(apiTokenEntity.isValid());
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidCheckTime());
            } else {
                assertTrue(apiTokenEntity.isValid());
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidCheckTime()));
            }
        }

        // verify the access token
        assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "error", "Failed to obtain new subtoken"))
        ));
    }

    @WithGw2AuthLogin
    public void consentSubmitWithLaterRemovedRootApiTokens(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the subtokens have been updated
        clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        Set<String> savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        final List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ));

        // remove all Root-Tokens for this authorization
        for (ClientAuthorizationTokenEntity clientAuthorizationTokenEntity : clientAuthorizationTokenEntities) {
            this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(clientAuthorizationTokenEntity.accountId(), clientAuthorizationTokenEntity.gw2AccountId());
        }

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        performRetrieveTokensByRefreshToken(clientRegistrationCreation, refreshToken)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").isString())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn();
    }

    @WithGw2AuthLogin
    public void consentSubmitWithLessScopesThanRequested(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.TRADINGPOST.oauth2())).andReturn();

        // read request information from redirected uri
        final Map<String, String> params = Utils.parseQuery(URI.create(result.getResponse().getRedirectedUrl()).getRawQuery())
                .filter(QueryParam::hasValue)
                .collect(Collectors.toMap(QueryParam::name, QueryParam::value));

        assertTrue(params.containsKey(OAuth2ParameterNames.CLIENT_ID));
        assertTrue(params.containsKey(OAuth2ParameterNames.STATE));
        assertTrue(params.containsKey(OAuth2ParameterNames.SCOPE));

        // insert a dummy api token
        this.testHelper.createApiToken(accountId, this.gw2AccountId1st, "TokenA", Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.TRADINGPOST), "First");

        // lookup the consent info (containing the submit uri and parameters that should be submitted)
        result = this.mockMvc.perform(
                get("/api/oauth2/consent")
                        .with(cookieHolder)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID))
                        .queryParam(OAuth2ParameterNames.STATE, params.get(OAuth2ParameterNames.STATE))
                        .queryParam(OAuth2ParameterNames.SCOPE, params.get(OAuth2ParameterNames.SCOPE))
        )
                .andDo(cookieHolder)
                .andReturn();

        // read the consent info and build the submit request
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode consentInfo = mapper.readTree(result.getResponse().getContentAsString());
        final String submitUri = consentInfo.get("submitFormUri").textValue();

        MockHttpServletRequestBuilder builder = post(submitUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .with(cookieHolder)
                .with(csrf());

        for (Map.Entry<String, JsonNode> entry : (Iterable<? extends Map.Entry<String, JsonNode>>) () -> consentInfo.get("submitFormParameters").fields()) {
            final String name = entry.getKey();
            final JsonNode values = entry.getValue();

            for (int i = 0; i < values.size(); i++) {
                final String value = values.get(i).textValue();

                // exclude the tradingpost scope
                if (!name.equals(OAuth2ParameterNames.SCOPE) || !value.equals(Gw2ApiPermission.TRADINGPOST.oauth2())) {
                    builder = builder.param(name, value);
                }
            }
        }

        final JsonNode apiTokensWithSufficientPermissions = consentInfo.get("apiTokensWithSufficientPermissions");

        assertEquals(1, apiTokensWithSufficientPermissions.size());
        assertEquals(0, consentInfo.get("apiTokensWithInsufficientPermissions").size());

        for (int i = 0; i < apiTokensWithSufficientPermissions.size(); i++) {
            builder = builder.param("token:" + apiTokensWithSufficientPermissions.get(i).get("gw2AccountId").textValue(), "");
        }

        // submit the consent
        this.mockMvc.perform(builder)
                .andDo(cookieHolder)
                .andExpect(status().isBadRequest());

        // authorization should not be saved
        final ClientConsentEntity clientAuthorization = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);

        // null is ok too
        if (clientAuthorization != null) {
            assertTrue(clientAuthorization.authorizedScopes().isEmpty());
        }
    }

    @WithGw2AuthLogin
    public void consentSubmitWithGw2AuthVerifiedScope(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), GW2AUTH_VERIFIED_SCOPE)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), GW2AUTH_VERIFIED_SCOPE), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), GW2AUTH_VERIFIED_SCOPE), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // save account verification for one account
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(this.gw2AccountId1st, accountId));

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCode(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]),
                Set.of(Gw2ApiPermission.ACCOUNT)
        )
                .andExpectAll(expectValidTokenResponse(Gw2ApiPermission.ACCOUNT.oauth2(), GW2AUTH_VERIFIED_SCOPE))
                .andReturn();

        // verify the authorized tokens have been updated
        Set<String> savedSubtokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        final List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0], "verified", true)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0], "verified", false))
        ));

        // remove the verification for the first account and save one for the second
        this.gw2AccountVerificationRepository.deleteByGw2AccountId(this.gw2AccountId1st);
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(this.gw2AccountId2nd, accountId));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(clientRegistrationCreation, refreshToken)
                .andExpectAll(expectValidTokenResponse(Gw2ApiPermission.ACCOUNT.oauth2(), GW2AUTH_VERIFIED_SCOPE))
                .andReturn();

        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0], "verified", false)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0], "verified", true))
        ));
    }

    @WithGw2AuthLogin
    public void consentSubmitAndSubmitAgainWithLessScopes(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS)).andReturn();

        // verify the consent has been saved
        ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        final ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2()), clientAuthorization.authorizedScopes());

        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCode(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]),
                Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS)
        )
                .andExpectAll(expectValidTokenResponse(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2()))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ), Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS));

        final String firstAuthorizationSubtokenA = dummySubtokenA[0];
        final String firstAuthorizationSubtokenB = dummySubtokenB[0];
        final JsonNode firstAuthorizationResponse = tokenResponse;

        // perform a new authorization
        // perform authorization request (which should redirect to application)
        result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2()), false).andReturn();

        // verify the consent is unchanged
        clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2()), clientConsentEntity.authorizedScopes());

        // verify both authorizations exist
        clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // retrieve the initial access and refresh token
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        dummySubtokenB[0] = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the access token
        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA[0])),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB[0]))
        ));

        // retrieve a new access and refresh token for the first authorization
        result = performRetrieveTokensByRefreshToken(
                clientRegistrationCreation,
                firstAuthorizationResponse.get("refresh_token").textValue()
        )
                .andExpectAll(expectValidTokenResponse(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.UNLOCKS.oauth2()))
                .andReturn();

        // verify the access token
        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", firstAuthorizationSubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", firstAuthorizationSubtokenB))
        ), Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS));
    }

    @WithGw2AuthLogin
    public void revokeAccessToken(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // revoke the access_token
        final String accessToken = tokenResponse.get("access_token").textValue();

        this.mockMvc.perform(
                post("/oauth2/revoke")
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                        .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                        .queryParam(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.ACCESS_TOKEN.getValue())
                        .queryParam(OAuth2ParameterNames.TOKEN, accessToken)
        )
                .andExpect(status().isOk());

        // database should still contain the authorization
        final List<ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @WithGw2AuthLogin
    public void revokeAccessTokenWithInvalidClientSecret(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // revoke the access_token
        final String accessToken = tokenResponse.get("access_token").textValue();

        this.mockMvc.perform(
                        post("/oauth2/revoke")
                                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, "Not the correct client secret")
                                .queryParam(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.ACCESS_TOKEN.getValue())
                                .queryParam(OAuth2ParameterNames.TOKEN, accessToken)
                )
                .andExpect(status().isUnauthorized());

        // database should still contain the authorization
        final List<ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @WithGw2AuthLogin
    public void revokeRefreshToken(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer & authorization service
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);
        this.clientAuthorizationService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // revoke the refresh_token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();

        this.mockMvc.perform(
                        post("/oauth2/revoke")
                                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                                .queryParam(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue())
                                .queryParam(OAuth2ParameterNames.TOKEN, refreshToken)
                )
                .andExpect(status().isOk());

        // trigger deletion
        this.clientAuthorizationService.deleteAllExpiredAuthorizations();

        // database should still contain the authorization (access token is still valid)
        List<ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(1, clientAuthorizationEntities.size());

        // trigger deletion with current timestamp + 31min
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.clientAuthorizationService.setClock(testingClock);
        this.clientAuthorizationService.deleteAllExpiredAuthorizations();

        // database should not contain the authorization anymore
        clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(0, clientAuthorizationEntities.size());
    }

    @WithGw2AuthLogin
    public void revokeRefreshTokenWithInvalidClientSecret(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        // revoke the refresh_token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();

        this.mockMvc.perform(
                        post("/oauth2/revoke")
                                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, "Not the correct client secret")
                                .queryParam(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue())
                                .queryParam(OAuth2ParameterNames.TOKEN, refreshToken)
                )
                .andExpect(status().isUnauthorized());

        // database should still contain the authorization
        final List<ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistration.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @WithGw2AuthLogin(issuer = "testissuer", idAtIssuer = "testidatissuer")
    public void refreshWithLegacyAttributes(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationCreation clientRegistrationCreation = createClientRegistration();
        final ClientRegistration clientRegistration = clientRegistrationCreation.clientRegistration();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(cookieHolder, clientRegistration, List.of(Gw2ApiPermission.ACCOUNT.oauth2())).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(cookieHolder, clientRegistration, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistration.id()).orElse(null);
        assertNotNull(clientConsentEntity);
        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientConsentEntity.authorizedScopes());

        // verify the authorization has been saved
        List<ClientAuthorizationEntity> authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        assertEquals(1, authorizations.size());

        ClientAuthorizationEntity clientAuthorization = authorizations.get(0);

        assertEquals(Set.of(Gw2ApiPermission.ACCOUNT.oauth2()), clientAuthorization.authorizedScopes());

        // verify the tokens have been saved
        List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorization.id());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.oAuth2TokenCustomizerService.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                clientRegistrationCreation,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the subtokens have been saved
        final Set<String> subTokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                        accountId,
                        Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                        Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
                )
                .stream()
                .map(ApiSubTokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toSet());

        assertEquals(2, subTokens.size());
        assertTrue(subTokens.contains(dummySubtokenA));
        assertTrue(subTokens.contains(dummySubtokenB));

        // verify the validity status has been saved
        final List<ApiTokenEntity> apiTokenEntities = this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertTrue(apiTokenEntities.get(0).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertTrue(apiTokenEntities.get(1).isValid());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        authorizations = this.clientAuthorizationRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientConsentEntity.clientRegistrationId());
        clientAuthorization = authorizations.get(0);

        // simulate the old format attributes
        String attributesJson = """
                        {
                          "@class": "java.util.HashMap",
                          "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest": {
                            "@class": "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest",
                            "authorizationUri": "http://127.0.0.1:9000/oauth2/authorize",
                            "authorizationGrantType": {
                              "value": "authorization_code"
                            },
                            "responseType": {
                              "value": "code"
                            },
                            "clientId": "__CLIENT_ID",
                            "redirectUri": "__REDIRECT_URI",
                            "scopes": [
                              "java.util.Collections$UnmodifiableSet",
                              [
                                "gw2:account"
                              ]
                            ],
                            "state": "__STATE",
                            "additionalParameters": {
                              "@class": "java.util.Collections$UnmodifiableMap",
                              "code_challenge": "__CODE_CHALLENGE",
                              "code_challenge_method": "S256"
                            },
                            "authorizationRequestUri": "http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=__CLIENT_ID&scope=gw2:account&state=uxAer3ibHweuGm0hVMdNzA&redirect_uri=__REDIRECT_URI&code_challenge=__CODE_CHALLENGE&code_challenge_method=S256",
                            "attributes": {
                              "@class": "java.util.Collections$UnmodifiableMap"
                            }
                          },
                          "java.security.Principal": {
                            "@class": "org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken",
                            "principal": {
                              "@class": "com.gw2auth.oauth2.server.service.user.Gw2AuthUser",
                              "parent": {
                                "@class": "org.springframework.security.oauth2.core.user.DefaultOAuth2User",
                                "authorities": [
                                  "java.util.Collections$UnmodifiableSet",
                                  [
                                    {
                                      "@class": "org.springframework.security.oauth2.core.user.OAuth2UserAuthority",
                                      "authority": "ROLE_USER",
                                      "attributes": {
                                        "@class": "java.util.Collections$UnmodifiableMap",
                                        "login": "its-felix",
                                        "created_at": "2016-11-21T13:52:43Z",
                                        "updated_at": "2022-04-11T22:57:12Z"
                                      }
                                    },
                                    {
                                      "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
                                      "authority": "SCOPE_"
                                    }
                                  ]
                                ],
                                "attributes": {
                                  "@class": "java.util.Collections$UnmodifiableMap",
                                  "login": "its-felix",
                                  "id": "testidatissuer",
                                  "created_at": "2016-11-21T13:52:43Z",
                                  "updated_at": "2022-04-11T22:57:12Z"
                                },
                                "nameAttributeKey": "id"
                              },
                              "accountId": "__ACCOUNT_ID"
                            },
                            "authorities": [
                              "java.util.Collections$UnmodifiableRandomAccessList",
                              [
                                {
                                  "@class": "org.springframework.security.oauth2.core.user.OAuth2UserAuthority",
                                  "authority": "ROLE_USER",
                                  "attributes": {
                                    "@class": "java.util.Collections$UnmodifiableMap",
                                    "login": "its-felix",
                                    "created_at": "2016-11-21T13:52:43Z",
                                    "updated_at": "2022-04-11T22:57:12Z"
                                  }
                                },
                                {
                                  "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
                                  "authority": "SCOPE_"
                                }
                              ]
                            ],
                            "authorizedClientRegistrationId": "testissuer",
                            "details": {
                              "@class": "org.springframework.security.web.authentication.WebAuthenticationDetails",
                              "remoteAddress": "127.0.0.1",
                              "sessionId": "5f935ea9-a65a-4504-bed7-bbc4286fe7e0"
                            }
                          }
                        }
                """;

        attributesJson = attributesJson.replace("__CLIENT_ID", clientRegistration.id().toString());
        attributesJson = attributesJson.replace("__REDIRECT_URI", TestHelper.first(clientRegistration.redirectUris()).orElseThrow());
        attributesJson = attributesJson.replace("__STATE", UUID.randomUUID().toString());
        attributesJson = attributesJson.replace("__CODE_CHALLENGE", UUID.randomUUID().toString());
        attributesJson = attributesJson.replace("__ACCOUNT_ID", accountId.toString());

        this.testHelper.executeUpdate("UPDATE client_authorizations SET attributes = ? WHERE id = ?", attributesJson, clientAuthorization.id());

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(clientRegistrationCreation, refreshToken).andReturn();

        tokenResponse = assertTokenResponse(result, () -> Map.of(
                this.gw2AccountId1st, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "First", "token", dummySubtokenA)),
                this.gw2AccountId2nd, new com.nimbusds.jose.shaded.json.JSONObject(Map.of("name", "Second", "token", dummySubtokenB))
        ));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    private ResultActions performRetrieveTokensByRefreshTokenAndExpectValid(ClientRegistrationCreation clientRegistrationCreation, String refreshToken) throws Exception {
        return performRetrieveTokensByRefreshToken(clientRegistrationCreation, refreshToken)
                .andExpectAll(expectValidTokenResponse());
    }

    private ResultActions performRetrieveTokensByRefreshToken(ClientRegistrationCreation clientRegistrationCreation, String refreshToken) throws Exception {
        return this.mockMvc.perform(
                        post("/oauth2/token")
                                .queryParam(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
                                .queryParam(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken)
                                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                );
    }

    private ResultActions performRetrieveTokenByCodeAndExpectValid(ClientRegistrationCreation clientRegistrationCreation, URI redirectedURI, Map<String, String> subtokenByGw2ApiToken) throws Exception {
        return performRetrieveTokenByCode(clientRegistrationCreation, redirectedURI, subtokenByGw2ApiToken, Set.of(Gw2ApiPermission.ACCOUNT))
                .andExpectAll(expectValidTokenResponse());
    }

    private ResultActions performRetrieveTokenByCode(ClientRegistrationCreation clientRegistrationCreation, URI redirectedURI, Map<String, String> subtokenByGw2ApiToken, Set<Gw2ApiPermission> expectedGw2ApiPermissions) throws Exception {
        final String codeParam = Utils.parseQuery(redirectedURI.getRawQuery())
                .filter(QueryParam::hasValue)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.CODE))
                .map(QueryParam::value)
                .findFirst()
                .orElse(null);

        assertNotNull(codeParam);

        // prepare the mocked gw2 api server to respond with dummy JWTs
        prepareGw2RestServerForCreateSubToken(subtokenByGw2ApiToken, expectedGw2ApiPermissions);

        // retrieve an access token
        // dont use the user session here!
        return this.mockMvc.perform(
                        post("/oauth2/token")
                                .queryParam(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                                .queryParam(OAuth2ParameterNames.CODE, codeParam)
                                .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistrationCreation.clientRegistration().id().toString())
                                .queryParam(OAuth2ParameterNames.CLIENT_SECRET, clientRegistrationCreation.clientSecret())
                                .queryParam(OAuth2ParameterNames.REDIRECT_URI, TestHelper.first(clientRegistrationCreation.clientRegistration().redirectUris()).orElseThrow())
                );
    }

    private void prepareGw2RestServerForCreateSubToken(Map<String, String> subtokenByGw2ApiToken) {
        prepareGw2RestServerForCreateSubToken(subtokenByGw2ApiToken, Set.of(Gw2ApiPermission.ACCOUNT));
    }

    private void prepareGw2RestServerForCreateSubToken(Map<String, String> subtokenByGw2ApiToken, Set<Gw2ApiPermission> expectedGw2ApiPermissions) {
        final String[] expectedGw2ApiPermissionStrs = expectedGw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).toArray(String[]::new);

        this.gw2RestServer.reset();
        this.gw2RestServer.expect(times(subtokenByGw2ApiToken.size()), requestTo(new StringStartsWith("/v2/createsubtoken")))
                .andExpect(method(HttpMethod.GET))
                .andExpect(MockRestRequestMatchers.header("Authorization", new StringStartsWith("Bearer ")))
                .andExpect(queryParam("permissions", split(",", containingAll(expectedGw2ApiPermissionStrs))))
                .andExpect(queryParam("expire", asInstant(instantWithinTolerance(Instant.now().plus(Duration.ofMinutes(30L)), Duration.ofSeconds(5L)))))
                .andRespond((request) -> {
                    final String gw2ApiToken = request.getHeaders().getFirst("Authorization").replaceFirst("Bearer ", "");
                    final String subtoken = subtokenByGw2ApiToken.get(gw2ApiToken);

                    if (subtoken == null || subtoken.isEmpty()) {
                        return new MockClientHttpResponse(new byte[0], HttpStatus.UNAUTHORIZED);
                    }

                    final MockClientHttpResponse response = new MockClientHttpResponse(new JSONObject(Map.of("subtoken", subtoken)).toString().getBytes(StandardCharsets.UTF_8), HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    return response;
                });
    }

    private ResultActions performSubmitConsent(CookieHolder cookieHolder, ClientRegistration clientRegistration, URI redirectedURI, String tokenA, String tokenB, String tokenC) throws Exception {
        return performSubmitConsent(cookieHolder, clientRegistration, redirectedURI, tokenA, tokenB, tokenC, Set.of(Gw2ApiPermission.ACCOUNT));
    }

    private ResultActions performSubmitConsent(CookieHolder cookieHolder, ClientRegistration clientRegistration, URI redirectedURI, String tokenA, String tokenB, String tokenC, Set<Gw2ApiPermission> requestedGw2ApiPermissions) throws Exception {
        // read request information from redirected uri
        final Map<String, String> params = Utils.parseQuery(redirectedURI.getRawQuery())
                .filter(QueryParam::hasValue)
                .collect(Collectors.toMap(QueryParam::name, QueryParam::value));

        assertTrue(params.containsKey(OAuth2ParameterNames.CLIENT_ID));
        assertTrue(params.containsKey(OAuth2ParameterNames.STATE));
        assertTrue(params.containsKey(OAuth2ParameterNames.SCOPE));

        // insert some dummy api tokens
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();

        this.testHelper.createApiToken(accountId, this.gw2AccountId1st, tokenA, requestedGw2ApiPermissions, "First");
        this.testHelper.createApiToken(accountId, this.gw2AccountId2nd, tokenB, requestedGw2ApiPermissions, "Second");
        this.testHelper.createApiToken(accountId, this.gw2AccountId3rd, tokenC, Set.of(), "Third");

        // lookup the consent info (containing the submit uri and parameters that should be submitted)
        MvcResult result = this.mockMvc.perform(
                get("/api/oauth2/consent")
                        .with(cookieHolder)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID))
                        .queryParam(OAuth2ParameterNames.STATE, params.get(OAuth2ParameterNames.STATE))
                        .queryParam(OAuth2ParameterNames.SCOPE, params.get(OAuth2ParameterNames.SCOPE))
        )
                .andDo(cookieHolder)
                .andReturn();

        // read the consent info and build the submit request
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode consentInfo = mapper.readTree(result.getResponse().getContentAsString());
        final String submitUri = consentInfo.get("submitFormUri").textValue();

        MockHttpServletRequestBuilder builder = post(submitUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .with(cookieHolder)
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
        return this.mockMvc.perform(builder)
                .andDo(cookieHolder)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new AllOf<>(
                        new StringStartsWith(TestHelper.first(clientRegistration.redirectUris()).orElseThrow()),
                        asUri(new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, hasQueryParam(OAuth2ParameterNames.CODE)))
                )));
    }

    private JsonNode assertTokenResponse(MvcResult result, Supplier<Map<UUID, com.nimbusds.jose.shaded.json.JSONObject>> expectedTokenSupplier) throws Exception {
        return assertTokenResponse(result, expectedTokenSupplier, Set.of(Gw2ApiPermission.ACCOUNT));
    }

    private JsonNode assertTokenResponse(MvcResult result, Supplier<Map<UUID, com.nimbusds.jose.shaded.json.JSONObject>> expectedTokenSupplier, Set<Gw2ApiPermission> expectedGw2ApiPermissions) throws Exception {
        final JsonNode tokenResponse = new ObjectMapper().readTree(result.getResponse().getContentAsString());

        // access token
        final JWT accessToken = JWTParser.parse(tokenResponse.get("access_token").textValue());
        assertNotNull(accessToken.getJWTClaimsSet().getIssueTime());
        assertNotNull(accessToken.getJWTClaimsSet().getExpirationTime());

        final Set<String> expectedGw2ApiPermissionStrs = expectedGw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet());

        assertEquals(expectedGw2ApiPermissionStrs, new HashSet<>(accessToken.getJWTClaimsSet().getStringListClaim("gw2:permissions")));

        final Map<UUID, com.nimbusds.jose.shaded.json.JSONObject> expectedTokens = new HashMap<>(expectedTokenSupplier.get());

        for (Map.Entry<String, Object> entry : accessToken.getJWTClaimsSet().getJSONObjectClaim("gw2:tokens").entrySet()) {
            final UUID gw2AccountId = UUID.fromString(entry.getKey());
            final com.nimbusds.jose.shaded.json.JSONObject token = (com.nimbusds.jose.shaded.json.JSONObject) entry.getValue();
            final com.nimbusds.jose.shaded.json.JSONObject expectedToken = expectedTokens.remove(gw2AccountId);

            assertNotNull(expectedToken);
            assertEquals(expectedToken, token);
        }

        assertTrue(expectedTokens.isEmpty());

        // refresh token
        assertTrue(tokenResponse.has("refresh_token"));
        assertTrue(tokenResponse.get("refresh_token").isTextual());

        return tokenResponse;
    }

    private ResultMatcher[] expectValidTokenResponse(String... expectedScopes) {
        return new ResultMatcher[]{
                status().isOk(),
                jsonPath("$.refresh_token").isString(),
                jsonPath("$.access_token").isString(),
                jsonPath("$.token_type").value("Bearer"),
                jsonPath("$.scope", split(" ", containingAll(expectedScopes))),
                jsonPath("$.expires_in").isNumber()
        };
    }

    private ResultMatcher[] expectValidTokenResponse() {
        return expectValidTokenResponse(Gw2ApiPermission.ACCOUNT.oauth2());
    }

    private ResultActions performAuthorizeWithNewClient(CookieHolder cookieHolder) throws Exception {
        return performAuthorizeWithNewClient(cookieHolder, List.of(Gw2ApiPermission.ACCOUNT.oauth2()));
    }

    private ResultActions performAuthorizeWithNewClient(CookieHolder cookieHolder, List<String> scopes) throws Exception {
        return performAuthorizeWithClient(cookieHolder, createClientRegistration().clientRegistration(), scopes, false);
    }

    private ResultActions performAuthorizeWithClient(CookieHolder cookieHolder, ClientRegistration clientRegistration, List<String> scopes) throws Exception {
        return performAuthorizeWithClient(cookieHolder, clientRegistration, scopes, false);
    }

    private ResultActions performAuthorizeWithClient(CookieHolder cookieHolder, ClientRegistration clientRegistration, List<String> scopes, boolean promptConsent) throws Exception {
        MockHttpServletRequestBuilder builder = get("/oauth2/authorize")
                // simulates a browser request for HTML; if not set it will return a 401 instead of redirecting to /login
                .accept(MediaType.TEXT_HTML, MediaType.ALL);

        if (cookieHolder != null) {
            builder = builder.with(cookieHolder);
        }

        if (promptConsent) {
            builder = builder.queryParam("prompt", "consent");
        }

        ResultActions resultActions =  this.mockMvc.perform(
                builder
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistration.id().toString())
                        .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", scopes))
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, TestHelper.first(clientRegistration.redirectUris()).orElseThrow())
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        );

        if (cookieHolder != null) {
            resultActions = resultActions.andDo(cookieHolder);
        }

        return resultActions;
    }

    private ClientRegistrationCreation createClientRegistration() {
        final Account account = this.accountService.getOrCreateAccount(UUID.randomUUID().toString(), UUID.randomUUID().toString());
        return this.clientRegistrationService.createClientRegistration(account.id(), "Test", Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()), Set.of("https://clientapplication.gw2auth.com/callback"));
    }
}
