package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientRepository;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.summary.SummaryServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Assertions.assertJsonArrayContainsExactly;
import static com.gw2auth.oauth2.server.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class ClientRegistrationControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationRepository applicationRepository;

    @Autowired
    private ApplicationClientRepository applicationClientRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private SummaryServiceImpl summaryService;

    @Autowired
    private TestHelper testHelper;

    @AfterEach
    public void resetClock() {
        this.summaryService.setClock(Clock.systemUTC());
    }

    @Test
    public void getClientRegistrationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/registration"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationsEmpty(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(get("/api/client/registration").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("0"));
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrations(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final ApplicationClientEntity applicationClientEntityA = this.testHelper.createClientRegistration(accountId, "NameA");
        final ApplicationClientEntity applicationClientEntityB = this.testHelper.createClientRegistration(accountId, "NameB");

        final String responseJson = this.mockMvc.perform(get("/api/client/registration").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("2"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode responseNode = mapper.readTree(responseJson);
        assertTrue(responseNode.isArray());

        Instant previousCreationTime = Instant.MIN;

        boolean foundA = false;
        boolean foundB = false;

        for (int i = 0; i < responseNode.size(); i++) {
            final JsonNode clientRegistrationNode = responseNode.get(i);
            final UUID clientId = UUID.fromString(clientRegistrationNode.get("clientId").textValue());
            final ApplicationClientEntity applicationClientEntity;

            if (clientId.equals(applicationClientEntityA.id())) {
                if (foundA) {
                    fail("Received A twice");
                    return;
                } else {
                    foundA = true;
                    applicationClientEntity = applicationClientEntityA;
                }
            } else if (clientId.equals(applicationClientEntityB.id())) {
                if (foundB) {
                    fail("Received B twice");
                    return;
                } else {
                    foundB = true;
                    applicationClientEntity = applicationClientEntityB;
                }
            } else {
                fail("Received unknown ClientRegistration");
                return;
            }

            assertClientRegistrationEquals(applicationClientEntity, clientRegistrationNode);

            final Instant creationTime = Instant.parse(clientRegistrationNode.get("creationTime").textValue());
            assertTrue(previousCreationTime.isBefore(creationTime));
            previousCreationTime = creationTime;
        }
    }

    @Test
    public void getClientRegistrationUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/registration/someid"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(get("/api/client/registration/{clientId}", applicationClientEntity.id()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationNotExisting(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(get("/api/client/registration/{clientId}", UUID.randomUUID()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistration(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");

        this.mockMvc.perform(get("/api/client/registration/{clientId}", applicationClientEntity.id()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(applicationClientEntity.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(applicationClientEntity.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll(applicationClientEntity.redirectUris())))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("2"));
    }

    @Test
    public void getClientRegistrationSummaryUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/registration/someid/summary"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationSummaryOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(get("/api/client/registration/{clientId}/summary", applicationClientEntity.id()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationSummaryNotExisting(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(get("/api/client/registration/{clientId}/summary", UUID.randomUUID()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientRegistrationSummary(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final Instant now = Instant.now();
        final Clock clock = Clock.fixed(now, ZoneId.systemDefault());
        this.summaryService.setClock(clock);

        final List<Gw2AccountApiTokenEntity> apiTokens = List.of(
                this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenA").v2(),
                this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenB").v2()
        );

        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");
        final ApplicationClientAccountEntity applicationClientAccountEntity = this.testHelper.createClientConsent(accountId, applicationClientEntity.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));

        final List<ApplicationClientAuthorizationEntity> clientAuthorizations = List.of(
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now, applicationClientAccountEntity, false), // this one should not be counted (no tokens)
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(31L)), applicationClientAccountEntity, true), // this one should not be counted (too long ago)
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(29L)), applicationClientAccountEntity, true),
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(8L)), applicationClientAccountEntity, true),
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(6L)), applicationClientAccountEntity, true),
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(4L)), applicationClientAccountEntity, true),
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now.minus(Duration.ofDays(2L)), applicationClientAccountEntity, true),
                this.testHelper.createClientAuthorization(accountId, applicationClientEntity.id(), now, applicationClientAccountEntity, true)
        );

        for (ApplicationClientAuthorizationEntity clientAuthorization : clientAuthorizations) {
            for (Gw2AccountApiTokenEntity apiToken : apiTokens) {
                this.testHelper.createClientAuthorizationTokens(clientAuthorization.accountId(), clientAuthorization.id(), apiToken.gw2AccountId());
            }
        }

        this.mockMvc.perform(get("/api/client/registration/{clientId}/summary", applicationClientEntity.id()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accounts").value(1L))
                .andExpect(jsonPath("$.gw2Accounts").value(2L))
                .andExpect(jsonPath("$.authPast1d").value(1L))
                .andExpect(jsonPath("$.authPast3d").value(2L))
                .andExpect(jsonPath("$.authPast7d").value(4L))
                .andExpect(jsonPath("$.authPast30d").value(6L));
    }

    @Test
    public void deleteClientRegistrationUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteClientRegistrationOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", applicationClientEntity.id()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteClientRegistrationNotExisting(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/{clientId}", UUID.randomUUID()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteClientRegistration(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", applicationClientEntity.id()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        assertTrue(this.applicationClientRepository.findById(applicationClientEntity.id()).isEmpty());
        assertTrue(this.applicationRepository.findById(applicationClientEntity.applicationId()).isEmpty());
    }

    @Test
    public void createClientRegistrationUnauthenticated() throws Exception {
        this.mockMvc.perform(
                post("/api/client/registration")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUri": "http://127.0.0.1/"}
                        """)
        )
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void createClientRegistrationMissingParameters(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test"}
                        """)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void createClientRegistrationInvalidRedirectURI(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUris": ["http://localhost/"]}
                        """)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void createClientRegistration(SessionHandle sessionHandle) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUris": ["http://127.0.0.1/a/b/c"]}
                        """)
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").isString())
                .andExpect(jsonPath("$.clientRegistration.creationTime").isString())
                .andExpect(jsonPath("$.clientRegistration.displayName").value("Test"))
                .andExpect(jsonPath("$.clientRegistration.clientId").isString())
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes.length()").value("1"))
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes[0]").value("authorization_code"))
                .andExpect(jsonPath("$.clientRegistration.redirectUris").value(containingAll("http://127.0.0.1/a/b/c")));

        assertEquals(1, this.applicationClientRepository.findAllByAccountId(this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow()).size());
    }

    @Test
    public void addRedirectUriUnauthenticated() throws Exception {
        this.mockMvc.perform(
                        put("/api/client/registration/some-id/redirect-uris")
                                .with(csrf())
                                .contentType(MediaType.TEXT_PLAIN)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addRedirectUriOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.TEXT_PLAIN)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addInvalidRedirectUri(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.TEXT_PLAIN)
                                .content("http://localhost/account/client/debug")
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void addRedirectUri(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(
                accountId,
                "NameA",
                Set.of("http://127.0.0.1/a", "http://127.0.0.1/account/client/debug")
        );

        final Set<String> expectedTotal = new HashSet<>(applicationClientEntity.redirectUris());
        expectedTotal.add("http://127.0.0.1/account/client/debug");

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.TEXT_PLAIN)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(applicationClientEntity.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(applicationClientEntity.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll(expectedTotal)))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("2"));

        applicationClientEntity = this.applicationClientRepository.findById(applicationClientEntity.id()).orElseThrow();
        assertEquals(Set.of("http://127.0.0.1/a", "http://127.0.0.1/account/client/debug"), applicationClientEntity.redirectUris());
    }

    @Test
    public void removeRedirectUriUnauthenticated() throws Exception {
        this.mockMvc.perform(
                        delete("/api/client/registration/some-id/redirect-uris")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://127.0.0.1/account/client/debug")
                )
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void removeRedirectUriOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://127.0.0.1/account/client/debug")
                )
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void removeLastRedirectUri(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");

        assertEquals(1, applicationClientEntity.redirectUris().size());

        final String redirectUri = applicationClientEntity.redirectUris().stream().findAny().orElseThrow();

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", redirectUri)
                )
                .andDo(sessionHandle)
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void removeRedirectUri(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(
                accountId,
                "NameA",
                Set.of("http://test.gw2auth.com/dummy", "http://test.gw2auth.com/dummy2")
        );

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://test.gw2auth.com/dummy")
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(applicationClientEntity.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(applicationClientEntity.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll("http://test.gw2auth.com/dummy2")))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("2"));

        applicationClientEntity = this.applicationClientRepository.findById(applicationClientEntity.id()).orElseThrow();
        assertEquals(Set.of("http://test.gw2auth.com/dummy2"), applicationClientEntity.redirectUris());
    }

    @Test
    public void regenerateClientSecretUnauthenticated() throws Exception {
        this.mockMvc.perform(
                        patch("/api/client/registration/some-id/client-secret")
                                .with(csrf())
                )
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void regenerateClientSecretOfOtherUser(SessionHandle sessionHandle) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(otherUserAccountId, "NameA");

        this.mockMvc.perform(
                        patch("/api/client/registration/{clientId}/client-secret", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                )
                .andDo(sessionHandle)
                .andExpect(status().isNotFound());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void regenerateClientSecret(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();
        ApplicationClientEntity applicationClientEntity = this.testHelper.createClientRegistration(accountId, "NameA");

        final String notExpectedClientSecret = applicationClientEntity.clientSecret();

        this.mockMvc.perform(
                        patch("/api/client/registration/{clientId}/client-secret", applicationClientEntity.id())
                                .with(sessionHandle)
                                .with(csrf())
                )
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").isString())
                .andExpect(jsonPath("$.clientRegistration.creationTime").value(asInstant(instant(applicationClientEntity.creationTime()))))
                .andExpect(jsonPath("$.clientRegistration.displayName").value(applicationClientEntity.displayName()))
                .andExpect(jsonPath("$.clientRegistration.redirectUris").value(containingAll(applicationClientEntity.redirectUris())))
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes.length()").value("2"));

        applicationClientEntity = this.applicationClientRepository.findById(applicationClientEntity.id()).orElseThrow();
        assertNotEquals(notExpectedClientSecret, applicationClientEntity.clientSecret());
    }

    private void assertClientRegistrationEquals(ApplicationClientEntity applicationClientEntity, JsonNode clientRegistrationNode) {
        assertInstantEquals(applicationClientEntity.creationTime(), clientRegistrationNode.get("creationTime").textValue());
        assertEquals(applicationClientEntity.displayName(), clientRegistrationNode.get("displayName").textValue());

        assertJsonArrayContainsExactly(clientRegistrationNode.get("authorizationGrantTypes"), applicationClientEntity.authorizationGrantTypes());
        assertJsonArrayContainsExactly(clientRegistrationNode.get("redirectUris"), applicationClientEntity.redirectUris());
    }
}