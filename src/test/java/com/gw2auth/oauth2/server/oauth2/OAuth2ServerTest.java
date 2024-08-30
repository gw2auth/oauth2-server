package com.gw2auth.oauth2.server.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.application.ApplicationEntity;
import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountRepository;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountSubRepository;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationWithGw2AccountIdsEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;
import com.gw2auth.oauth2.server.service.OAuth2ClientType;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientCreation;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationServiceImpl;
import com.gw2auth.oauth2.server.util.QueryParam;
import com.gw2auth.oauth2.server.util.Utils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.Part;
import org.hamcrest.core.AllOf;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.StringEndsWith;
import org.hamcrest.core.StringStartsWith;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.mock.web.MockPart;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
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
    @RegisterExtension
    Gw2AuthClockedExtension gw2AuthClockedExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationRepository applicationRepository;

    @Autowired
    private ApplicationAccountSubRepository applicationAccountSubRepository;

    @Autowired
    private ApplicationAccountRepository applicationAccountRepository;

    @Autowired
    private ApplicationClientService applicationClientService;

    @Autowired
    private ApplicationClientAccountRepository applicationClientAccountRepository;

    @Autowired
    private ApplicationClientAuthorizationServiceImpl applicationClientAuthorizationService;

    @Autowired
    private ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;

    @Autowired
    private ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository;

    @Autowired
    private Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;

    @Autowired
    private Gw2AccountApiSubtokenRepository gw2AccountApiSubtokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    @Qualifier("gw2-rest-server")
    private MockRestServiceServer gw2RestServer;

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
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth")))
                .andExpect(jsonPath("$.jwks_uri").value(org.hamcrest.Matchers.endsWith("/oauth2/jwks")))
                .andExpect(jsonPath("$.response_types_supported").value(containingAll("code")))
                .andExpect(jsonPath("$.grant_types_supported").value(containingAll("authorization_code","client_credentials","refresh_token","urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange")))
                .andExpect(jsonPath("$.revocation_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/revoke")))
                .andExpect(jsonPath("$.revocation_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth")))
                .andExpect(jsonPath("$.introspection_endpoint").value(org.hamcrest.Matchers.endsWith("/oauth2/introspect")))
                .andExpect(jsonPath("$.introspection_endpoint_auth_methods_supported").value(containingAll("client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth")))
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
                        .queryParam(OAuth2ParameterNames.SCOPE, OAuth2Scope.GW2_ACCOUNT.oauth2())
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, "http://127.0.0.1/")
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        ).andExpect(status().isBadRequest());
    }

    @Test
    public void authorizationCodeRequestNotLoggedIn() throws Exception {
        performAuthorizeWithNewClient(null, OAuth2ClientApiVersion.CURRENT, OAuth2ClientType.CONFIDENTIAL)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new StringEndsWith("/login")));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void authorizationCodeRequestConsent(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        performAuthorizeWithNewClient(sessionHandle, clientApiVersion, clientType, Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_TRADINGPOST))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2-consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(OAuth2Scope.GW2_ACCOUNT.oauth2(), OAuth2Scope.GW2_TRADINGPOST.oauth2())))
                        ))
                ))));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void authorizationCodeRequestWithExistingConsentButWithoutAPITokens(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClient applicationClient = createApplicationClient(clientApiVersion, clientType).client();

        this.applicationAccountSubRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                UUID.randomUUID()
        );

        this.applicationAccountRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                Instant.now()
        );

        this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                applicationClient.id(),
                accountId,
                applicationClient.applicationId(),
                ApplicationClientAccount.ApprovalStatus.APPROVED.name(),
                "UNIT-TEST",
                Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2-consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.SCOPE),
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE)
                        ))
                ))));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void authorizationCodeRequestWithUpgradingConsent(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClient applicationClient = createApplicationClient(clientApiVersion, clientType).client();

        this.applicationAccountSubRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                UUID.randomUUID()
        );

        this.applicationAccountRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                Instant.now()
        );

        this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                applicationClient.id(),
                accountId,
                applicationClient.applicationId(),
                ApplicationClientAccount.ApprovalStatus.APPROVED.name(),
                "UNIT-TEST",
                Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_INVENTORIES))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2-consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(OAuth2Scope.GW2_ACCOUNT.oauth2(), OAuth2Scope.GW2_INVENTORIES.oauth2())))
                        ))
                ))));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void authorizationCodeRequestWithExistingConsentAndPromptConsent(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClient applicationClient = createApplicationClient(clientApiVersion, clientType).client();

        this.applicationAccountSubRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                UUID.randomUUID()
        );

        this.applicationAccountRepository.findOrCreate(
                applicationClient.applicationId(),
                accountId,
                Instant.now()
        );

        this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                applicationClient.id(),
                accountId,
                applicationClient.applicationId(),
                ApplicationClientAccount.ApprovalStatus.APPROVED.name(),
                "UNIT-TEST",
                Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2())
        ));

        performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT), true)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", asUri(new AllOf<>(
                        new Matchers.MappingMatcher<>("Path", UriComponents::getPath, new IsEqual<>("/oauth2-consent")),
                        new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, new AllOf<>(
                                hasQueryParam(OAuth2ParameterNames.CLIENT_ID),
                                hasQueryParam(OAuth2ParameterNames.STATE),
                                hasQueryParam(OAuth2ParameterNames.SCOPE, split(" ", containingAll(OAuth2Scope.GW2_ACCOUNT.oauth2())))
                        ))
                ))));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowGeneric(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        // verify the tokens have been saved
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the subtokens have been saved
        final Set<String> subTokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, subTokens.size());
        assertTrue(subTokens.contains(dummySubtokenA));
        assertTrue(subTokens.contains(dummySubtokenB));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(applicationClient, clientSecret, refreshToken).andReturn();

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowWildcardRedirectUri(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType, "https://*.gw2auth.com/callback");
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT), "https://clientapplication.gw2auth.com/callback", false).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, "https://clientapplication.gw2auth.com/callback", URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC, Set.of(Gw2ApiPermission.ACCOUNT)).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        // verify the tokens have been saved
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                "https://clientapplication.gw2auth.com/callback",
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB),
                Set.of(Gw2ApiPermission.ACCOUNT)
        )
                .andExpectAll(expectValidTokenResponse())
                .andReturn();

        // verify the subtokens have been saved
        final Set<String> subTokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                        accountId,
                        Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                        Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
                )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, subTokens.size());
        assertTrue(subTokens.contains(dummySubtokenA));
        assertTrue(subTokens.contains(dummySubtokenB));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(applicationClient, clientSecret, refreshToken).andReturn();

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowV1_NoGw2AccRelatedScopes(SessionHandle sessionHandle, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(OAuth2ClientApiVersion.V1, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        final UUID accountSub = this.applicationAccountSubRepository.findOrCreate(applicationClient.applicationId(), accountId, UUID.randomUUID()).accountSub();

        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.ID)).andReturn();

        // submit the consent
        result = performSubmitConsent(
                sessionHandle,
                applicationClient,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                Set.of()
        ).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.ID.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();
        assertEquals(Set.of(OAuth2Scope.ID.oauth2()), clientAuthorization.authorization().authorizedScopes());
        assertEquals(0, clientAuthorization.gw2AccountIds().size());

        // verify no tokens have been saved
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(0, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(),
                Set.of()
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.ID))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponseV1(result, accountSub.toString(), Map.of(), Set.of(OAuth2Scope.ID));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.ID))
                .andReturn();

        tokenResponse = assertTokenResponseV1(result, accountSub.toString(), Map.of(), Set.of(OAuth2Scope.ID));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowV1_Gw2AccNameScope(SessionHandle sessionHandle, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(OAuth2ClientApiVersion.V1, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        final UUID accountSub = this.applicationAccountSubRepository.findOrCreate(applicationClient.applicationId(), accountId, UUID.randomUUID()).accountSub();

        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2ACC_NAME)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();

        // submit the consent
        result = performSubmitConsent(
                sessionHandle,
                applicationClient,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(
                        this.gw2AccountId1st, "First.1234",
                        this.gw2AccountId2nd, "Second.1234",
                        this.gw2AccountId3rd, "Third.1234"
                ),
                Map.of(
                        this.gw2AccountId1st, "First",
                        this.gw2AccountId2nd, "Second",
                        this.gw2AccountId3rd, "Third"
                ),
                Map.of(
                        this.gw2AccountId1st, tokenA,
                        this.gw2AccountId2nd, tokenB,
                        this.gw2AccountId3rd, tokenC
                ),
                Map.of(
                        this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT),
                        this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT),
                        this.gw2AccountId3rd, Set.of(Gw2ApiPermission.ACCOUNT)
                ),
                Set.of()
        ).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2ACC_NAME.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();
        assertEquals(Set.of(OAuth2Scope.GW2ACC_NAME.oauth2()), clientAuthorization.authorization().authorizedScopes());
        assertEquals(3, clientAuthorization.gw2AccountIds().size());

        // verify the accounts have been saved with the authorization
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(3, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(),
                Set.of()
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2ACC_NAME))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponseV1(
                result,
                null,
                Map.of(
                        this.gw2AccountId1st, Map.of("name", "First.1234"),
                        this.gw2AccountId2nd, Map.of("name", "Second.1234"),
                        this.gw2AccountId3rd, Map.of("name", "Third.1234")
                ),
                Set.of(OAuth2Scope.GW2ACC_NAME)
        );

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2ACC_NAME))
                .andReturn();

        tokenResponse = assertTokenResponseV1(
                result,
                null,
                Map.of(
                        this.gw2AccountId1st, Map.of("name", "First.1234"),
                        this.gw2AccountId2nd, Map.of("name", "Second.1234"),
                        this.gw2AccountId3rd, Map.of("name", "Third.1234")
                ),
                Set.of(OAuth2Scope.GW2ACC_NAME)
        );

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowV1_Gw2AccDisplayNameScope(SessionHandle sessionHandle, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(OAuth2ClientApiVersion.V1, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        final UUID accountSub = this.applicationAccountSubRepository.findOrCreate(applicationClient.applicationId(), accountId, UUID.randomUUID()).accountSub();

        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2ACC_DISPLAY_NAME)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();

        // submit the consent
        result = performSubmitConsent(
                sessionHandle,
                applicationClient,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(
                        this.gw2AccountId1st, "First.1234",
                        this.gw2AccountId2nd, "Second.1234",
                        this.gw2AccountId3rd, "Third.1234"
                ),
                Map.of(
                        this.gw2AccountId1st, "First",
                        this.gw2AccountId2nd, "Second",
                        this.gw2AccountId3rd, "Third"
                ),
                Map.of(
                        this.gw2AccountId1st, tokenA,
                        this.gw2AccountId2nd, tokenB,
                        this.gw2AccountId3rd, tokenC
                ),
                Map.of(
                        this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT),
                        this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT),
                        this.gw2AccountId3rd, Set.of(Gw2ApiPermission.ACCOUNT)
                ),
                Set.of()
        ).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2ACC_DISPLAY_NAME.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();
        assertEquals(Set.of(OAuth2Scope.GW2ACC_DISPLAY_NAME.oauth2()), clientAuthorization.authorization().authorizedScopes());
        assertEquals(3, clientAuthorization.gw2AccountIds().size());

        // verify the accounts have been saved with the authorization
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(3, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(),
                Set.of()
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2ACC_DISPLAY_NAME))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponseV1(
                result,
                null,
                Map.of(
                        this.gw2AccountId1st, Map.of("display_name", "First"),
                        this.gw2AccountId2nd, Map.of("display_name", "Second"),
                        this.gw2AccountId3rd, Map.of("display_name", "Third")
                ),
                Set.of(OAuth2Scope.GW2ACC_DISPLAY_NAME)
        );

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2ACC_DISPLAY_NAME))
                .andReturn();

        tokenResponse = assertTokenResponseV1(
                result,
                null,
                Map.of(
                        this.gw2AccountId1st, Map.of("display_name", "First"),
                        this.gw2AccountId2nd, Map.of("display_name", "Second"),
                        this.gw2AccountId3rd, Map.of("display_name", "Third")
                ),
                Set.of(OAuth2Scope.GW2ACC_DISPLAY_NAME)
        );

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientType
    public void consentSubmitAndHappyFlowV1_AllV1Scopes(SessionHandle sessionHandle, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(OAuth2ClientApiVersion.V1, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        final UUID accountSub = this.applicationAccountSubRepository.findOrCreate(applicationClient.applicationId(), accountId, UUID.randomUUID()).accountSub();

        final Set<OAuth2Scope> scopes = OAuth2Scope.allForVersion(OAuth2ClientApiVersion.V1).collect(Collectors.toUnmodifiableSet());
        final Set<String> scopeStrs = scopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet());

        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, scopes).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();

        // submit the consent
        result = performSubmitConsent(
                sessionHandle,
                applicationClient,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(
                        this.gw2AccountId1st, "First.1234",
                        this.gw2AccountId2nd, "Second.1234",
                        this.gw2AccountId3rd, "Third.1234"
                ),
                Map.of(
                        this.gw2AccountId1st, "First",
                        this.gw2AccountId2nd, "Second",
                        this.gw2AccountId3rd, "Third"
                ),
                Map.of(
                        this.gw2AccountId1st, tokenA,
                        this.gw2AccountId2nd, tokenB,
                        this.gw2AccountId3rd, tokenC
                ),
                Map.of(
                        this.gw2AccountId1st, Gw2ApiPermission.all(),
                        this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT),
                        this.gw2AccountId3rd, Gw2ApiPermission.all()
                ),
                Gw2ApiPermission.all()
        ).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(scopeStrs, applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();
        assertEquals(scopeStrs, clientAuthorization.authorization().authorizedScopes());
        assertEquals(2, clientAuthorization.gw2AccountIds().size());

        // verify the accounts have been saved with the authorization
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // create dummy subtokens
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Gw2ApiPermission.all(), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenC = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId3rd, Gw2ApiPermission.all(), testingClock.instant(), Duration.ofMinutes(30L))};

        // save account verification for one account
        this.gw2AccountVerificationRepository.save(this.gw2AccountId1st, accountId);

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(
                        tokenA, dummySubtokenA[0],
                        tokenC, dummySubtokenC[0]
                ),
                Gw2ApiPermission.all()
        )
                .andExpectAll(expectValidTokenResponse(scopes))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponseV1(
                result,
                accountSub.toString(),
                Map.of(
                        this.gw2AccountId1st, Map.of(
                                "name", "First.1234",
                                "display_name", "First",
                                "verified", true,
                                "token", dummySubtokenA[0]
                        ),
                        this.gw2AccountId3rd, Map.of(
                                "name", "Third.1234",
                                "display_name", "Third",
                                "verified", false,
                                "token", dummySubtokenC[0]
                        )
                ),
                scopes
        );

        // save account verification for second account
        this.gw2AccountVerificationRepository.save(this.gw2AccountId3rd, accountId);

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse(scopes))
                .andReturn();

        tokenResponse = assertTokenResponseV1(
                result,
                accountSub.toString(),
                Map.of(
                        this.gw2AccountId1st, Map.of(
                                "name", "First.1234",
                                "display_name", "First",
                                "verified", true,
                                "token", dummySubtokenA[0]
                        ),
                        this.gw2AccountId3rd, Map.of(
                                "name", "Third.1234",
                                "display_name", "Third",
                                "verified", true,
                                "token", dummySubtokenC[0]
                        )
                ),
                scopes
        );

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithExpiredSubtokens(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(
                        tokenA, dummySubtokenA[0],
                        tokenB, dummySubtokenB[0]
                )
        ).andReturn();

        // verify the subtokens have been updated
        clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        Set<String> savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // prepare the gw2 reset api for new subtoken requests
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        dummySubtokenB[0] = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        prepareGw2RestServerForCreateSubToken(Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]));

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.gw2AuthClockedExtension.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(applicationClient, clientSecret, refreshToken).andReturn();

        // verify the subtokens have been updated
        savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the new response
        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithSubtokenRetrievalError(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the subtokens been updated
        Set<String> savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // prepare the gw2 reset api for new subtoken requests (dont return a new subtoken for TokenB in this testcase)
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        prepareGw2RestServerForCreateSubToken(Map.of(tokenA, dummySubtokenA[0], tokenB, ""));

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.gw2AuthClockedExtension.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(applicationClient, clientSecret, refreshToken).andReturn();

        // verify the subtokens have been updated, but only for one
        savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved, but only for the first one
        apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());

        for (Gw2AccountApiTokenEntity apiTokenEntity : apiTokenEntities) {
            if (apiTokenEntity.gw2AccountId().equals(this.gw2AccountId1st)) {
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidTime());
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidCheckTime());
            } else {
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidTime()));
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidCheckTime()));
            }
        }

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "error", "Failed to obtain new subtoken")
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithUnexpectedGW2APIException(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

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
                multipart(HttpMethod.POST, "/oauth2/token")
                        .part(part(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()))
                        .part(part(OAuth2ParameterNames.CODE, codeParam))
                        .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                        .part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret))
                        .part(part(OAuth2ParameterNames.REDIRECT_URI, TestHelper.first(applicationClient.redirectUris()).orElseThrow()))
        )
                .andExpectAll(expectValidTokenResponse())
                .andReturn();

        // verify the subtokens have been updated
        final Set<String> savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(1, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());

        for (Gw2AccountApiTokenEntity apiTokenEntity : apiTokenEntities) {
            if (apiTokenEntity.gw2AccountId().equals(this.gw2AccountId1st)) {
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidTime());
                assertInstantEquals(testingClock.instant(), apiTokenEntity.lastValidCheckTime());
            } else {
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidTime()));
                assertTrue(testingClock.instant().isAfter(apiTokenEntity.lastValidCheckTime()));
            }
        }

        // verify the access token
        assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "error", "Failed to obtain new subtoken")
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithLaterRemovedRootApiTokens(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the subtokens have been updated
        clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        Set<String> savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // remove all Root-Tokens for this authorization
        for (ApplicationClientAuthorizationTokenEntity clientAuthorizationTokenEntity : clientAuthorizationTokenEntities) {
            this.gw2AccountApiTokenRepository.deleteByAccountIdAndGw2AccountId(clientAuthorizationTokenEntity.accountId(), clientAuthorizationTokenEntity.gw2AccountId());
        }

        // retrieve a new access token using the refresh token
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.gw2AuthClockedExtension.setClock(testingClock);

        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse())
                .andReturn();

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "error", "Failed to obtain new subtoken"),
                this.gw2AccountId2nd, Map.of("name", "Second", "error", "Failed to obtain new subtoken")
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithLessScopesThanRequested(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClient applicationClient = createApplicationClient(clientApiVersion, clientType).client();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_TRADINGPOST)).andReturn();

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
                        .with(sessionHandle)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID))
                        .queryParam(OAuth2ParameterNames.STATE, params.get(OAuth2ParameterNames.STATE))
                        .queryParam(OAuth2ParameterNames.SCOPE, params.get(OAuth2ParameterNames.SCOPE))
        )
                .andDo(sessionHandle)
                .andReturn();

        // read the consent info and build the submit request
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode consentInfo = mapper.readTree(result.getResponse().getContentAsString());
        final String submitUri = consentInfo.get("submitFormUri").textValue();

        MockHttpServletRequestBuilder builder = post(submitUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .with(sessionHandle)
                .with(csrf());

        for (Map.Entry<String, JsonNode> entry : (Iterable<? extends Map.Entry<String, JsonNode>>) () -> consentInfo.get("submitFormParameters").fields()) {
            final String name = entry.getKey();
            final JsonNode values = entry.getValue();

            for (int i = 0; i < values.size(); i++) {
                final String value = values.get(i).textValue();

                // exclude the tradingpost scope
                if (!name.equals(OAuth2ParameterNames.SCOPE) || !value.equals(OAuth2Scope.GW2_TRADINGPOST.oauth2())) {
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
                .andDo(sessionHandle)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new AllOf<>(
                        new StringStartsWith(TestHelper.first(applicationClient.redirectUris()).orElseThrow()),
                        asUri(new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, hasQueryParam(OAuth2ParameterNames.ERROR, "invalid_scope")))
                )));

        // consent should not be saved (or have empty scopes)
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);

        // null is ok too
        if (applicationClientAccountEntity != null) {
            assertTrue(applicationClientAccountEntity.authorizedScopes().isEmpty());
        }
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitWithGw2AuthVerifiedScope(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        final Set<OAuth2Scope> scopes = switch (clientApiVersion) {
            case V0 -> Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED);
            case V1 -> Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2ACC_VERIFIED);
        };
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, scopes).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(scopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(scopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // save account verification for one account
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(this.gw2AccountId1st, accountId));

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]),
                Set.of(Gw2ApiPermission.ACCOUNT)
        )
                .andExpectAll(expectValidTokenResponse(scopes.toArray(OAuth2Scope[]::new)))
                .andReturn();

        // verify the authorized tokens have been updated
        Set<String> savedSubtokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                accountId,
                Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
        )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, savedSubtokens.size());
        assertTrue(savedSubtokens.contains(dummySubtokenA[0]));
        assertTrue(savedSubtokens.contains(dummySubtokenB[0]));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0], "verified", true),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0], "verified", false)
        ), scopes.stream().collect(Collectors.toUnmodifiableSet()));

        // remove the verification for the first account and save one for the second
        this.gw2AccountVerificationRepository.deleteByGw2AccountId(this.gw2AccountId1st);
        this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(this.gw2AccountId2nd, accountId));

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse(scopes.toArray(OAuth2Scope[]::new)))
                .andReturn();

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0], "verified", false),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0], "verified", true)
        ), scopes.stream().collect(Collectors.toUnmodifiableSet()));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void consentSubmitAndSubmitAgainWithLessScopes(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_UNLOCKS)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS)).andReturn();

        // verify the consent has been saved
        ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2(), OAuth2Scope.GW2_UNLOCKS.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2(), OAuth2Scope.GW2_UNLOCKS.oauth2()), clientAuthorization.authorization().authorizedScopes());

        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorization.gw2AccountIds().size());
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String[] dummySubtokenA = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS), testingClock.instant(), Duration.ofMinutes(30L))};
        final String[] dummySubtokenB = new String[]{TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS), testingClock.instant(), Duration.ofMinutes(30L))};

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0]),
                Set.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.UNLOCKS)
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_UNLOCKS))
                .andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_UNLOCKS));

        final String firstAuthorizationSubtokenA = dummySubtokenA[0];
        final String firstAuthorizationSubtokenB = dummySubtokenB[0];
        final JsonNode firstAuthorizationResponse = tokenResponse;

        // perform a new authorization
        // perform authorization request (which should redirect to application)
        result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT), false).andReturn();

        // verify the consent is unchanged
        applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2(), OAuth2Scope.GW2_UNLOCKS.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify both authorizations exist
        clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // retrieve the initial access and refresh token
        dummySubtokenA[0] = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        dummySubtokenB[0] = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA[0], tokenB, dummySubtokenB[0])
        ).andReturn();

        // verify the access token
        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA[0]),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB[0])
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // retrieve a new access and refresh token for the first authorization
        result = performRetrieveTokensByRefreshToken(
                applicationClient,
                clientSecret,
                firstAuthorizationResponse.get("refresh_token").textValue()
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_UNLOCKS))
                .andReturn();

        // verify the access token
        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", firstAuthorizationSubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", firstAuthorizationSubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_UNLOCKS));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void retrieveAccessTokenWithInvalidClientSecret(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        performRetrieveTokenByCode(
                applicationClient,
                "invalid_client_secret",
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB),
                Set.of(Gw2ApiPermission.ACCOUNT)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    @ParameterizedTest
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void retrieveAccessTokenWithInvalidCode(OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();

        performRetrieveTokenByCode(
                applicationClient,
                applicationClientCreation.clientSecret(),
                TestHelper.first(applicationClient.redirectUris()).orElseThrow(),
                "invalid_code"
        )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_GRANT));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void revokeAccessToken(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // revoke the access_token
        final String accessToken = tokenResponse.get("access_token").textValue();

        this.mockMvc.perform(
                multipart(HttpMethod.POST, "/oauth2/revoke")
                        .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                        .part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret))
                        .part(part(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.ACCESS_TOKEN.getValue()))
                        .part(part(OAuth2ParameterNames.TOKEN, accessToken))
        )
                .andExpect(status().isOk());

        // database should still contain the authorization
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> clientAuthorizationEntities = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void revokeAccessTokenWithInvalidClientSecret(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // revoke the access_token
        final String accessToken = tokenResponse.get("access_token").textValue();

        this.mockMvc.perform(
                        multipart(HttpMethod.POST, "/oauth2/revoke")
                                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                                .part(part(OAuth2ParameterNames.CLIENT_SECRET, "Not the correct client secret"))
                                .part(part(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.ACCESS_TOKEN.getValue()))
                                .part(part(OAuth2ParameterNames.TOKEN, accessToken))
                )
                .andExpect(status().isUnauthorized());

        // database should still contain the authorization
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> clientAuthorizationEntities = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void revokeRefreshToken(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer & authorization service
        Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // revoke the refresh_token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();

        this.mockMvc.perform(
                        multipart(HttpMethod.POST, "/oauth2/revoke")
                                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                                .part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret))
                                .part(part(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue()))
                                .part(part(OAuth2ParameterNames.TOKEN, refreshToken))
                )
                .andExpect(status().isOk());

        // trigger deletion
        this.applicationClientAuthorizationService.deleteAllExpiredAuthorizations();

        // database should still contain the authorization (access token is still valid)
        List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> clientAuthorizationEntities = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, clientAuthorizationEntities.size());

        // trigger deletion with current timestamp + 31min
        testingClock = Clock.offset(testingClock, Duration.ofMinutes(31L));
        this.gw2AuthClockedExtension.setClock(testingClock);
        this.applicationClientAuthorizationService.deleteAllExpiredAuthorizations();

        // database should not contain the authorization anymore
        clientAuthorizationEntities = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(0, clientAuthorizationEntities.size());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void revokeRefreshTokenWithInvalidClientSecret(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        // revoke the refresh_token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();

        this.mockMvc.perform(
                        multipart(HttpMethod.POST, "/oauth2/revoke")
                                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                                .part(part(OAuth2ParameterNames.CLIENT_SECRET, "Not the correct client secret"))
                                .part(part(OAuth2ParameterNames.TOKEN_TYPE_HINT, OAuth2TokenType.REFRESH_TOKEN.getValue()))
                                .part(part(OAuth2ParameterNames.TOKEN, refreshToken))
                )
                .andExpect(status().isUnauthorized());

        // database should still contain the authorization
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> clientAuthorizationEntities = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, clientAuthorizationEntities.size());
    }

    @ParameterizedTest
    @WithGw2AuthLogin(issuer = "testissuer", idAtIssuer = "testidatissuer")
    @WithOAuth2ClientApiVersion
    @WithOAuth2ClientType
    public void refreshWithLegacyAttributes(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(clientApiVersion, clientType);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();
        // perform authorization request (which should redirect to the consent page)
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // submit the consent
        final String tokenA = TestHelper.randomRootToken();
        final String tokenB = TestHelper.randomRootToken();
        final String tokenC = TestHelper.randomRootToken();
        result = performSubmitConsent(sessionHandle, applicationClient, URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())), tokenA, tokenB, tokenC).andReturn();

        // verify the consent has been saved
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClientAccountEntity.applicationClientId());
        assertEquals(1, authorizations.size());

        ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();

        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());

        // verify the authorization entity has all tokens
        assertEquals(2, clientAuthorization.gw2AccountIds().size());

        // verify the tokens have been saved
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(2, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        // retrieve the initial access and refresh token
        final String dummySubtokenA = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));
        final String dummySubtokenB = TestHelper.createSubtokenJWT(this.gw2AccountId2nd, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCodeAndExpectValid(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(tokenA, dummySubtokenA, tokenB, dummySubtokenB)
        ).andReturn();

        // verify the subtokens have been saved
        final Set<String> subTokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(
                        accountId,
                        Set.of(this.gw2AccountId1st, this.gw2AccountId2nd),
                        Gw2ApiPermission.toBitSet(Set.of(Gw2ApiPermission.ACCOUNT))
                )
                .stream()
                .map(Gw2AccountApiSubtokenEntity::gw2ApiSubtoken)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(2, subTokens.size());
        assertTrue(subTokens.contains(dummySubtokenA));
        assertTrue(subTokens.contains(dummySubtokenB));

        // verify the validity status has been saved
        final List<Gw2AccountApiTokenEntity> apiTokenEntities = this.gw2AccountApiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, Set.of(this.gw2AccountId1st, this.gw2AccountId2nd));
        assertEquals(2, apiTokenEntities.size());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(0).lastValidCheckTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidTime());
        assertInstantEquals(testingClock.instant(), apiTokenEntities.get(1).lastValidCheckTime());

        // verify the access token
        JsonNode tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClientAccountEntity.applicationClientId());
        clientAuthorization = authorizations.getFirst();

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

        attributesJson = attributesJson.replace("__CLIENT_ID", applicationClient.id().toString());
        attributesJson = attributesJson.replace("__REDIRECT_URI", TestHelper.first(applicationClient.redirectUris()).orElseThrow());
        attributesJson = attributesJson.replace("__STATE", UUID.randomUUID().toString());
        attributesJson = attributesJson.replace("__CODE_CHALLENGE", UUID.randomUUID().toString());
        attributesJson = attributesJson.replace("__ACCOUNT_ID", accountId.toString());

        this.testHelper.executeUpdate("UPDATE application_client_authorizations SET attributes = ? WHERE id = ?", attributesJson, clientAuthorization.authorization().id());

        // retrieve a new access token using the refresh token
        final String refreshToken = tokenResponse.get("refresh_token").textValue();
        result = performRetrieveTokensByRefreshTokenAndExpectValid(applicationClient, clientSecret, refreshToken).andReturn();

        tokenResponse = assertTokenResponse(clientApiVersion, result, Map.of(
                this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtokenA),
                this.gw2AccountId2nd, Map.of("name", "Second", "token", dummySubtokenB)
        ), Set.of(OAuth2Scope.GW2_ACCOUNT));

        assertNotEquals(refreshToken, tokenResponse.get("refresh_token").textValue());
    }

    @Test
    public void unauthenticatedRequestShouldRememberURLAndRedirectUponLogin() throws Exception {
        final ApplicationClientCreation applicationClientCreation = createApplicationClient(OAuth2ClientApiVersion.V0, OAuth2ClientType.CONFIDENTIAL);
        final ApplicationClient applicationClient = applicationClientCreation.client();
        final String clientSecret = applicationClientCreation.clientSecret();

        // perform authorization request (should redirect to the login page)
        final SessionHandle sessionHandle = new SessionHandle();
        MvcResult result = performAuthorizeWithClient(sessionHandle, applicationClient, Set.of(OAuth2Scope.GW2_ACCOUNT)).andReturn();

        // verify the redirect URI was saved
        assertNotNull(sessionHandle.getCookie("REDIRECT_URI"));

        // login
        result = this.gw2AuthLoginExtension.login(sessionHandle, "issuer", UUID.randomUUID().toString())
                .andExpectAll(this.gw2AuthLoginExtension.expectLoginSuccess())
                .andReturn();

        // verify the redirect URI was removed
        assertNull(sessionHandle.getCookie("REDIRECT_URI"));

        // follow redirect
        result = this.mockMvc.perform(
                get(URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())))
                        .with(sessionHandle)
        )
                .andDo(sessionHandle)
                .andReturn();

        // submit the consent
        final String token = TestHelper.randomRootToken();
        result = performSubmitConsent(
                sessionHandle,
                applicationClient,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(this.gw2AccountId1st, "First.1234"),
                Map.of(this.gw2AccountId1st, "First"),
                Map.of(this.gw2AccountId1st, token),
                Map.of(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT)),
                Set.of(Gw2ApiPermission.ACCOUNT)
        ).andReturn();

        // verify the consent has been saved
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                applicationClient.id(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), applicationClientAccountEntity.authorizedScopes());

        // verify the authorization has been saved
        final List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> authorizations = this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClient.id());
        assertEquals(1, authorizations.size());

        final ApplicationClientAuthorizationWithGw2AccountIdsEntity clientAuthorization = authorizations.getFirst();
        assertEquals(Set.of(OAuth2Scope.GW2_ACCOUNT.oauth2()), clientAuthorization.authorization().authorizedScopes());
        assertEquals(Set.of(this.gw2AccountId1st), clientAuthorization.gw2AccountIds());

        // verify tokens have been saved
        List<ApplicationClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(clientAuthorization.authorization().id(), accountId);
        assertEquals(1, clientAuthorizationTokenEntities.size());

        // set testing clock to token customizer
        final Clock testingClock = Clock.fixed(Instant.now(), ZoneId.systemDefault());
        this.gw2AuthClockedExtension.setClock(testingClock);

        final String dummySubtoken = TestHelper.createSubtokenJWT(this.gw2AccountId1st, Set.of(Gw2ApiPermission.ACCOUNT), testingClock.instant(), Duration.ofMinutes(30L));

        result = performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                URI.create(Objects.requireNonNull(result.getResponse().getRedirectedUrl())),
                Map.of(token, dummySubtoken),
                Set.of(Gw2ApiPermission.ACCOUNT)
        )
                .andExpectAll(expectValidTokenResponse(OAuth2Scope.GW2_ACCOUNT))
                .andReturn();

        // verify the access token
        assertTokenResponseV0(
                result,
                Map.of(this.gw2AccountId1st, Map.of("name", "First", "token", dummySubtoken)),
                Set.of(OAuth2Scope.GW2_ACCOUNT)
        );
    }

    private ResultActions performRetrieveTokensByRefreshTokenAndExpectValid(ApplicationClient applicationClient, String clientSecret, String refreshToken) throws Exception {
        return performRetrieveTokensByRefreshToken(applicationClient, clientSecret, refreshToken)
                .andExpectAll(expectValidTokenResponse());
    }

    private ResultActions performRetrieveTokensByRefreshToken(ApplicationClient applicationClient, String clientSecret, String refreshToken) throws Exception {
        MockMultipartHttpServletRequestBuilder builder = multipart(HttpMethod.POST, "/oauth2/token")
                .part(part(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue()))
                .part(part(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken))
                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()));

        if (applicationClient.type() == OAuth2ClientType.CONFIDENTIAL) {
            builder = builder.part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret));
        } else {
            // builder = builder.queryParam("code_verifier", generateCodeChallenge(applicationClient));
        }

        return this.mockMvc.perform(builder);
    }

    private ResultActions performRetrieveTokenByCodeAndExpectValid(ApplicationClient applicationClient, String clientSecret, URI redirectedURI, Map<String, String> subtokenByGw2ApiToken) throws Exception {
        return performRetrieveTokenByCode(applicationClient, clientSecret, redirectedURI, subtokenByGw2ApiToken, Set.of(Gw2ApiPermission.ACCOUNT))
                .andExpectAll(expectValidTokenResponse());
    }

    private ResultActions performRetrieveTokenByCode(ApplicationClient applicationClient, String clientSecret, URI redirectedURI, Map<String, String> subtokenByGw2ApiToken, Set<Gw2ApiPermission> expectedGw2ApiPermissions) throws Exception {
        return performRetrieveTokenByCode(
                applicationClient,
                clientSecret,
                TestHelper.first(applicationClient.redirectUris()).orElseThrow(),
                redirectedURI,
                subtokenByGw2ApiToken,
                expectedGw2ApiPermissions
        );
    }

    private ResultActions performRetrieveTokenByCode(ApplicationClient applicationClient, String clientSecret, String redirectUri, URI redirectedURI, Map<String, String> subtokenByGw2ApiToken, Set<Gw2ApiPermission> expectedGw2ApiPermissions) throws Exception {
        final String codeParam = Utils.parseQuery(redirectedURI.getRawQuery())
                .filter(QueryParam::hasValue)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.CODE))
                .map(QueryParam::value)
                .findFirst()
                .orElse(null);

        assertNotNull(codeParam);

        // prepare the mocked gw2 api server to respond with dummy JWTs
        prepareGw2RestServerForCreateSubToken(subtokenByGw2ApiToken, expectedGw2ApiPermissions);

        MockMultipartHttpServletRequestBuilder builder = multipart(HttpMethod.POST, "/oauth2/token")
                .part(part(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()))
                .part(part(OAuth2ParameterNames.CODE, codeParam))
                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                .part(part(OAuth2ParameterNames.REDIRECT_URI, redirectUri));

        if (applicationClient.type() == OAuth2ClientType.CONFIDENTIAL) {
            builder = builder.part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret));
        } else {
            builder = builder.part(part("code_verifier", generateCodeChallenge(applicationClient)));
        }

        // retrieve an access token
        // dont use the user session here!
        return this.mockMvc.perform(builder);
    }

    private ResultActions performRetrieveTokenByCode(ApplicationClient applicationClient, String clientSecret, String redirectUri, String code) throws Exception {
        MockMultipartHttpServletRequestBuilder builder = multipart(HttpMethod.POST, "/oauth2/token")
                .part(part(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()))
                .part(part(OAuth2ParameterNames.CODE, code))
                .part(part(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString()))
                .part(part(OAuth2ParameterNames.REDIRECT_URI, redirectUri));

        if (applicationClient.type() == OAuth2ClientType.CONFIDENTIAL) {
            builder = builder.part(part(OAuth2ParameterNames.CLIENT_SECRET, clientSecret));
        } else {
            builder = builder.part(part("code_verifier", generateCodeChallenge(applicationClient)));
        }

        // retrieve an access token
        // dont use the user session here!
        return this.mockMvc.perform(builder);
    }

    private void prepareGw2RestServerForCreateSubToken(Map<String, String> subtokenByGw2ApiToken) {
        prepareGw2RestServerForCreateSubToken(subtokenByGw2ApiToken, Set.of(Gw2ApiPermission.ACCOUNT));
    }

    private void prepareGw2RestServerForCreateSubToken(Map<String, String> subtokenByGw2ApiToken, Set<Gw2ApiPermission> expectedGw2ApiPermissions) {
        final String[] expectedGw2ApiPermissionStrs = expectedGw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).toArray(String[]::new);

        this.gw2RestServer.reset();

        if (!subtokenByGw2ApiToken.isEmpty()) {
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
    }

    private ResultActions performSubmitConsent(SessionHandle sessionHandle, ApplicationClient applicationClient, URI redirectedURI, String tokenA, String tokenB, String tokenC) throws Exception {
        return performSubmitConsent(
                sessionHandle,
                applicationClient,
                redirectedURI,
                tokenA,
                tokenB,
                tokenC,
                Set.of(Gw2ApiPermission.ACCOUNT)
        );
    }

    private ResultActions performSubmitConsent(SessionHandle sessionHandle,
                                               ApplicationClient applicationClient,
                                               URI redirectedURI,
                                               String tokenA,
                                               String tokenB,
                                               String tokenC,
                                               Set<Gw2ApiPermission> gw2ApiPermissions) throws Exception {

        return performSubmitConsent(
                sessionHandle,
                TestHelper.first(applicationClient.redirectUris()).orElseThrow(),
                redirectedURI,
                tokenA,
                tokenB,
                tokenC,
                gw2ApiPermissions
        );
    }

    private ResultActions performSubmitConsent(SessionHandle sessionHandle,
                                               String redirectUri,
                                               URI redirectedURI,
                                               String tokenA,
                                               String tokenB,
                                               String tokenC,
                                               Set<Gw2ApiPermission> gw2ApiPermissions) throws Exception {

        return performSubmitConsent(
                sessionHandle,
                redirectUri,
                redirectedURI,
                Map.of(
                        this.gw2AccountId1st, "First.1234",
                        this.gw2AccountId2nd, "Second.1234",
                        this.gw2AccountId3rd, "Third.1234"
                ),
                Map.of(
                        this.gw2AccountId1st, "First",
                        this.gw2AccountId2nd, "Second",
                        this.gw2AccountId3rd, "Third"
                ),
                Map.of(
                        this.gw2AccountId1st, tokenA,
                        this.gw2AccountId2nd, tokenB,
                        this.gw2AccountId3rd, tokenC
                ),
                Map.of(
                        this.gw2AccountId1st, gw2ApiPermissions,
                        this.gw2AccountId2nd, gw2ApiPermissions,
                        this.gw2AccountId3rd, Set.of()
                ),
                gw2ApiPermissions
        );
    }

    private ResultActions performSubmitConsent(SessionHandle sessionHandle,
                                               ApplicationClient applicationClient,
                                               URI redirectedURI,
                                               Map<UUID, String> nameByGw2AccountId,
                                               Map<UUID, String> displayNameByGw2AccountId,
                                               Map<UUID, String> tokenByGw2AccountId,
                                               Map<UUID, Set<Gw2ApiPermission>> gw2ApiPermissionsByGw2AccountId,
                                               Set<Gw2ApiPermission> requestedGw2ApiPermissions) throws Exception {

        return performSubmitConsent(
                sessionHandle,
                TestHelper.first(applicationClient.redirectUris()).orElseThrow(),
                redirectedURI,
                nameByGw2AccountId,
                displayNameByGw2AccountId,
                tokenByGw2AccountId,
                gw2ApiPermissionsByGw2AccountId,
                requestedGw2ApiPermissions
        );
    }

    private ResultActions performSubmitConsent(SessionHandle sessionHandle,
                                               String redirectUri,
                                               URI redirectedURI,
                                               Map<UUID, String> nameByGw2AccountId,
                                               Map<UUID, String> displayNameByGw2AccountId,
                                               Map<UUID, String> tokenByGw2AccountId,
                                               Map<UUID, Set<Gw2ApiPermission>> gw2ApiPermissionsByGw2AccountId,
                                               Set<Gw2ApiPermission> requestedGw2ApiPermissions) throws Exception {

        // read request information from redirected uri
        final Map<String, String> params = Utils.parseQuery(redirectedURI.getRawQuery())
                .filter(QueryParam::hasValue)
                .collect(Collectors.toMap(QueryParam::name, QueryParam::value));

        assertTrue(params.containsKey(OAuth2ParameterNames.CLIENT_ID));
        assertTrue(params.containsKey(OAuth2ParameterNames.STATE));
        assertTrue(params.containsKey(OAuth2ParameterNames.SCOPE));

        // insert some dummy api tokens
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        int expectedSufficient = 0;
        int expectedInsufficient = 0;

        for (Map.Entry<UUID, String> entry : nameByGw2AccountId.entrySet()) {
            final UUID gw2AccountId = entry.getKey();
            final String name = entry.getValue();
            final String displayName = displayNameByGw2AccountId.getOrDefault(gw2AccountId, name);
            final String token = tokenByGw2AccountId.get(gw2AccountId);
            final Set<Gw2ApiPermission> gw2ApiPermissions = gw2ApiPermissionsByGw2AccountId.get(gw2AccountId);

            if (token != null && gw2ApiPermissions != null) {
                this.testHelper.createApiToken(accountId, gw2AccountId, token, gw2ApiPermissions, name, displayName);
            } else {
                this.testHelper.getOrCreateGw2Account(accountId, gw2AccountId, name, displayName);
            }

            if (requestedGw2ApiPermissions.isEmpty() || Objects.equals(gw2ApiPermissions, requestedGw2ApiPermissions)) {
                expectedSufficient++;
            } else {
                expectedInsufficient++;
            }
        }

        // lookup the consent info (containing the submit uri and parameters that should be submitted)
        MvcResult result = this.mockMvc.perform(
                get("/api/oauth2/consent")
                        .with(sessionHandle)
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, params.get(OAuth2ParameterNames.CLIENT_ID))
                        .queryParam(OAuth2ParameterNames.STATE, params.get(OAuth2ParameterNames.STATE))
                        .queryParam(OAuth2ParameterNames.SCOPE, params.get(OAuth2ParameterNames.SCOPE))
        )
                .andDo(sessionHandle)
                .andReturn();

        // read the consent info and build the submit request
        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode consentInfo = mapper.readTree(result.getResponse().getContentAsString());
        final String submitUri = consentInfo.get("submitFormUri").textValue();

        MockHttpServletRequestBuilder builder = post(submitUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .with(sessionHandle)
                .with(csrf());

        for (Map.Entry<String, JsonNode> entry : (Iterable<? extends Map.Entry<String, JsonNode>>) () -> consentInfo.get("submitFormParameters").fields()) {
            final String name = entry.getKey();
            final JsonNode values = entry.getValue();

            for (int i = 0; i < values.size(); i++) {
                builder = builder.param(name, values.get(i).textValue());
            }
        }

        final JsonNode apiTokensWithSufficientPermissions = consentInfo.get("apiTokensWithSufficientPermissions");

        assertEquals(expectedSufficient, apiTokensWithSufficientPermissions.size());
        assertEquals(expectedInsufficient, consentInfo.get("apiTokensWithInsufficientPermissions").size());

        for (int i = 0; i < apiTokensWithSufficientPermissions.size(); i++) {
            builder = builder.param("token:" + apiTokensWithSufficientPermissions.get(i).get("gw2AccountId").textValue(), "");
        }

        // submit the consent
        return this.mockMvc.perform(builder)
                .andDo(sessionHandle)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new AllOf<>(
                        new StringStartsWith(redirectUri),
                        asUri(new Matchers.MappingMatcher<>("Query", UriComponents::getQueryParams, hasQueryParam(OAuth2ParameterNames.CODE)))
                )));
    }

    private JsonNode assertTokenResponse(OAuth2ClientApiVersion clientApiVersion, MvcResult result, Map<UUID, Map<String, Object>> expectedTokens, Set<OAuth2Scope> expectedScopes) throws Exception {
        return switch (clientApiVersion) {
            case V0 -> assertTokenResponseV0(result, expectedTokens, expectedScopes);
            case V1 -> assertTokenResponseV1(result, expectedTokens, expectedScopes);
        };
    }

    private JsonNode assertTokenResponseV0(MvcResult result, Map<UUID, Map<String, Object>> expectedTokens, Set<OAuth2Scope> expectedScopes) throws Exception {
        final JsonNode tokenResponse = new ObjectMapper().readTree(result.getResponse().getContentAsString());

        // access token
        final JWT accessToken = JWTParser.parse(tokenResponse.get("access_token").textValue());
        assertNotNull(accessToken.getJWTClaimsSet().getIssueTime());
        assertNotNull(accessToken.getJWTClaimsSet().getExpirationTime());

        final Set<String> expectedGw2ApiPermissionStrs = expectedScopes.stream()
                .flatMap((v) -> Gw2ApiPermission.fromScope(v).stream())
                .map(Gw2ApiPermission::gw2)
                .collect(Collectors.toUnmodifiableSet());

        assertEquals(expectedGw2ApiPermissionStrs, new HashSet<>(accessToken.getJWTClaimsSet().getStringListClaim("gw2:permissions")));

        expectedTokens = new HashMap<>(expectedTokens);

        for (Map.Entry<String, Object> entry : accessToken.getJWTClaimsSet().getJSONObjectClaim("gw2:tokens").entrySet()) {
            final UUID gw2AccountId = UUID.fromString(entry.getKey());
            final Map<String, Object> token = (Map<String, Object>) entry.getValue();
            final Map<String, Object> expectedToken = expectedTokens.remove(gw2AccountId);

            assertNotNull(expectedToken);
            assertEquals(expectedToken, token);
        }

        assertTrue(expectedTokens.isEmpty());

        // refresh token
        assertTrue(tokenResponse.has("refresh_token"));
        assertTrue(tokenResponse.get("refresh_token").isTextual());

        // scopes
        final JsonNode scopeNode = tokenResponse.get("scope");
        assertTrue(scopeNode.isTextual());
        final Set<String> scopes = Utils.split(scopeNode.textValue(), " ").collect(Collectors.toUnmodifiableSet());
        assertEquals(expectedScopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet()), scopes);

        return tokenResponse;
    }

    private JsonNode assertTokenResponseV1(MvcResult result, Map<UUID, Map<String, Object>> expectedTokens, Set<OAuth2Scope> expectedScopes) throws Exception {
        final Map<UUID, Map<String, Object>> expectedAccounts = new HashMap<>();
        for (Map.Entry<UUID, Map<String, Object>> entry : expectedTokens.entrySet()) {
            final Map<String, Object> expectedAccount = entry.getValue().entrySet().stream()
                    .filter((v) -> !v.getKey().equals("name"))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            expectedAccounts.put(entry.getKey(), expectedAccount);
        }

        return assertTokenResponseV1(result, null, expectedAccounts, expectedScopes);
    }

    private JsonNode assertTokenResponseV1(MvcResult result, String expectedSubject, Map<UUID, Map<String, Object>> expectedAccounts, Set<OAuth2Scope> expectedScopes) throws Exception {
        final JsonNode tokenResponse = new ObjectMapper().readTree(result.getResponse().getContentAsString());

        // access token
        final JWT accessToken = JWTParser.parse(tokenResponse.get("access_token").textValue());
        assertNotNull(accessToken.getJWTClaimsSet().getIssueTime());
        assertNotNull(accessToken.getJWTClaimsSet().getExpirationTime());

        final String sub = accessToken.getJWTClaimsSet().getSubject();
        assertNotNull(sub);

        if (expectedSubject == null) {
            assertTrue(sub.startsWith("RETRACTED-"));
        } else {
            assertEquals(expectedSubject, sub);
        }

        if (!expectedAccounts.isEmpty()) {
            final Object gw2AccountsRaw = accessToken.getJWTClaimsSet().getClaim("gw2_accounts");
            assertNotNull(gw2AccountsRaw);

            final List<Map<String, Object>> actualAccounts = (List<Map<String, Object>>) gw2AccountsRaw;
            expectedAccounts = new HashMap<>(expectedAccounts);

            for (Map<String, Object> actualAccount : actualAccounts) {
                actualAccount = new HashMap<>(actualAccount);

                final Object id = actualAccount.remove("id");
                assertNotNull(id);

                final Map<String, Object> expectedAccount = expectedAccounts.remove(UUID.fromString(id.toString()));
                assertNotNull(expectedAccount);
                assertEquals(expectedAccount, actualAccount);
            }

            assertTrue(expectedAccounts.isEmpty());
        }

        // refresh token
        assertTrue(tokenResponse.has("refresh_token"));
        assertTrue(tokenResponse.get("refresh_token").isTextual());

        // scopes
        final JsonNode scopeNode = tokenResponse.get("scope");
        assertTrue(scopeNode.isTextual());
        final Set<String> scopes = Utils.split(scopeNode.textValue(), " ").collect(Collectors.toUnmodifiableSet());
        assertEquals(expectedScopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet()), scopes);

        return tokenResponse;
    }

    private ResultMatcher[] expectValidTokenResponse(OAuth2Scope... expectedScopes) {
        return expectValidTokenResponse(Arrays.stream(expectedScopes).collect(Collectors.toUnmodifiableSet()));
    }

    private ResultMatcher[] expectValidTokenResponse(Set<OAuth2Scope> expectedScopes) {
        final Set<String> rawScopes = expectedScopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.toUnmodifiableSet());

        return new ResultMatcher[]{
                status().isOk(),
                jsonPath("$.refresh_token").isString(),
                jsonPath("$.access_token").isString(),
                jsonPath("$.token_type").value("Bearer"),
                jsonPath("$.scope", split(" ", containingAll(rawScopes))),
                jsonPath("$.expires_in").isNumber()
        };
    }

    private ResultMatcher[] expectValidTokenResponse() {
        return expectValidTokenResponse(OAuth2Scope.GW2_ACCOUNT);
    }

    private ResultActions performAuthorizeWithNewClient(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) throws Exception {
        return performAuthorizeWithNewClient(sessionHandle, clientApiVersion, clientType, Set.of(OAuth2Scope.GW2_ACCOUNT));
    }

    private ResultActions performAuthorizeWithNewClient(SessionHandle sessionHandle, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType, Set<OAuth2Scope> scopes) throws Exception {
        return performAuthorizeWithClient(sessionHandle, createApplicationClient(clientApiVersion, clientType).client(), scopes, false);
    }

    private ResultActions performAuthorizeWithClient(SessionHandle sessionHandle, ApplicationClient applicationClient, Set<OAuth2Scope> scopes) throws Exception {
        return performAuthorizeWithClient(sessionHandle, applicationClient, scopes, false);
    }

    private ResultActions performAuthorizeWithClient(SessionHandle sessionHandle, ApplicationClient applicationClient, Set<OAuth2Scope> scopes, boolean promptConsent) throws Exception {
        return performAuthorizeWithClient(
                sessionHandle,
                applicationClient,
                scopes,
                TestHelper.first(applicationClient.redirectUris()).orElseThrow(),
                promptConsent
        );
    }

    private ResultActions performAuthorizeWithClient(SessionHandle sessionHandle, ApplicationClient applicationClient, Set<OAuth2Scope> scopes, String redirectUri, boolean promptConsent) throws Exception {
        MockHttpServletRequestBuilder builder = get("/oauth2/authorize")
                // simulates a browser request for HTML; if not set it will return a 401 instead of redirecting to /login
                .accept(MediaType.TEXT_HTML, MediaType.ALL);

        if (sessionHandle != null) {
            builder = builder.with(sessionHandle);
        }

        if (promptConsent) {
            builder = builder.queryParam("prompt", "consent");
        }

        if (applicationClient.type() == OAuth2ClientType.PUBLIC) {
            final String codeChallenge = generateCodeChallenge(applicationClient);
            final String b64CodeChallenge = encodeCodeChallenge(codeChallenge);

            builder = builder
                    .queryParam("code_challenge", b64CodeChallenge)
                    .queryParam("code_challenge_method", "S256");
        }

        ResultActions resultActions =  this.mockMvc.perform(
                builder
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, applicationClient.id().toString())
                        .queryParam(OAuth2ParameterNames.SCOPE, scopes.stream().map(OAuth2Scope::oauth2).collect(Collectors.joining(" ")))
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        );

        if (sessionHandle != null) {
            resultActions = resultActions.andDo(sessionHandle);
        }

        return resultActions;
    }

    private ApplicationClientCreation createApplicationClient(OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) {
        return createApplicationClient(clientApiVersion, clientType, "https://clientapplication.gw2auth.com/callback");
    }

    private ApplicationClientCreation createApplicationClient(OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType, String redirectUri) {
        // attach this client to a loose account
        final AccountEntity accountEntity = this.testHelper.createAccount();

        final ApplicationEntity applicationEntity = this.applicationRepository.save(new ApplicationEntity(
                UUID.randomUUID(),
                accountEntity.id(),
                Instant.now(),
                "Test App"
        ));

        return this.applicationClientService.createApplicationClient(
                accountEntity.id(),
                applicationEntity.id(),
                "Test",
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()),
                Set.of(redirectUri),
                clientApiVersion,
                clientType
        );
    }

    private static String generateCodeChallenge(ApplicationClient applicationClient) {
        return String.format("%s%s", applicationClient.id(), applicationClient.displayName());
    }

    private static String encodeCodeChallenge(String codeChallenge) {
        final MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        final byte[] bytes = md.digest(codeChallenge.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Part part(String name, String value) {
        return new MockPart(name, value.getBytes(StandardCharsets.UTF_8));
    }
}

