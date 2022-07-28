package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
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
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getClientRegistrationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/registration"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientRegistrationsEmpty(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(get("/api/client/registration").with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("0"));
    }

    @WithGw2AuthLogin
    public void getClientRegistrations(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();

        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameB", "SecretB", Set.of(), Set.of("http://127.0.0.1/b", "http://127.0.0.1/c")));

        final String responseJson = this.mockMvc.perform(get("/api/client/registration").with(cookieHolder))
                .andDo(cookieHolder)
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
            final ClientRegistrationEntity clientRegistration;

            if (clientId.equals(clientRegistrationA.id())) {
                if (foundA) {
                    fail("Received A twice");
                    return;
                } else {
                    foundA = true;
                    clientRegistration = clientRegistrationA;
                }
            } else if (clientId.equals(clientRegistrationB.id())) {
                if (foundB) {
                    fail("Received B twice");
                    return;
                } else {
                    foundB = true;
                    clientRegistration = clientRegistrationB;
                }
            } else {
                fail("Received unknown ClientRegistration");
                return;
            }

            assertClientRegistrationEquals(clientRegistration, clientRegistrationNode);

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

    @WithGw2AuthLogin
    public void getClientRegistrationOfOtherUser(CookieHolder cookieHolder) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), otherUserAccountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(get("/api/client/registration/{clientId}", clientRegistration.id()).with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void getClientRegistrationNotExisting(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(get("/api/client/registration/{clientId}", UUID.randomUUID()).with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void getClientRegistration(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity( UUID.randomUUID(), accountId, Instant.now(), "NameA","SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(get("/api/client/registration/{clientId}", clientRegistration.id()).with(cookieHolder))
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(clientRegistration.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(clientRegistration.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll(clientRegistration.redirectUris())))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("0"));
    }

    @Test
    public void deleteClientRegistrationUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistrationOfOtherUser(CookieHolder cookieHolder) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), otherUserAccountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", clientRegistration.id()).with(cookieHolder).with(csrf()))
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistrationNotExisting(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/{clientId}", UUID.randomUUID()).with(cookieHolder).with(csrf()))
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistration(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(),  accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", clientRegistration.id()).with(cookieHolder).with(csrf()))
                .andDo(cookieHolder)
                .andExpect(status().isOk());

        assertTrue(this.clientRegistrationRepository.findById(clientRegistration.id()).isEmpty());
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

    @WithGw2AuthLogin
    public void createClientRegistrationMissingParameters(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test"}
                        """)
                )
                .andDo(cookieHolder)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void createClientRegistrationInvalidRedirectURI(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUris": ["http://localhost/"]}
                        """)
                )
                .andDo(cookieHolder)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void createClientRegistration(CookieHolder cookieHolder) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUris": ["http://127.0.0.1/a/b/c"]}
                        """)
                )
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").isString())
                .andExpect(jsonPath("$.clientRegistration.creationTime").isString())
                .andExpect(jsonPath("$.clientRegistration.displayName").value("Test"))
                .andExpect(jsonPath("$.clientRegistration.clientId").isString())
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes.length()").value("1"))
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes[0]").value("authorization_code"))
                .andExpect(jsonPath("$.clientRegistration.redirectUris").value(containingAll("http://127.0.0.1/a/b/c")));

        assertEquals(1, this.clientRegistrationRepository.findAllByAccountId(this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow()).size());
    }

    @Test
    public void addRedirectUriUnauthenticated() throws Exception {
        this.mockMvc.perform(
                        put("/api/client/registration/some-id/redirect-uris")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void addRedirectUriOfOtherUser(CookieHolder cookieHolder) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), otherUserAccountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void addInvalidRedirectUri(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("http://localhost/account/client/debug")
                )
                .andDo(cookieHolder)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void addRedirectUri(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        put("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("http://127.0.0.1/account/client/debug")
                )
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(clientRegistration.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(clientRegistration.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll("http://127.0.0.1/a", "http://127.0.0.1/account/client/debug")))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("0"));

        clientRegistration = this.clientRegistrationRepository.findById(clientRegistration.id()).orElseThrow();
        assertEquals(Set.of("http://127.0.0.1/a", "http://127.0.0.1/account/client/debug"), clientRegistration.redirectUris());
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

    @WithGw2AuthLogin
    public void removeRedirectUriOfOtherUser(CookieHolder cookieHolder) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), otherUserAccountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://127.0.0.1/account/client/debug")
                )
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void removeLastRedirectUri(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://127.0.0.1/a")
                )
                .andDo(cookieHolder)
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void removeRedirectUri(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a", "http://127.0.0.1/b")));

        this.mockMvc.perform(
                        delete("/api/client/registration/{clientId}/redirect-uris", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .queryParam("redirectUri", "http://127.0.0.1/a")
                )
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(asInstant(instant(clientRegistration.creationTime()))))
                .andExpect(jsonPath("$.displayName").value(clientRegistration.displayName()))
                .andExpect(jsonPath("$.redirectUris").value(containingAll("http://127.0.0.1/b")))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("0"));

        clientRegistration = this.clientRegistrationRepository.findById(clientRegistration.id()).orElseThrow();
        assertEquals(Set.of("http://127.0.0.1/b"), clientRegistration.redirectUris());
    }

    @Test
    public void regenerateClientSecretUnauthenticated() throws Exception {
        this.mockMvc.perform(
                        patch("/api/client/registration/some-id/client-secret")
                                .with(csrf())
                )
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void regenerateClientSecretOfOtherUser(CookieHolder cookieHolder) throws Exception {
        final UUID otherUserAccountId = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), otherUserAccountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        patch("/api/client/registration/{clientId}/client-secret", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                )
                .andDo(cookieHolder)
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void regenerateClientSecret(CookieHolder cookieHolder) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(cookieHolder).orElseThrow();
        ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(UUID.randomUUID(), accountId, Instant.now(), "NameA", "SecretA", Set.of(), Set.of("http://127.0.0.1/a")));

        this.mockMvc.perform(
                        patch("/api/client/registration/{clientId}/client-secret", clientRegistration.id())
                                .with(cookieHolder)
                                .with(csrf())
                )
                .andDo(cookieHolder)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").isString())
                .andExpect(jsonPath("$.clientRegistration.creationTime").value(asInstant(instant(clientRegistration.creationTime()))))
                .andExpect(jsonPath("$.clientRegistration.displayName").value(clientRegistration.displayName()))
                .andExpect(jsonPath("$.clientRegistration.redirectUris").value(containingAll(clientRegistration.redirectUris())))
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes.length()").value("0"));

        clientRegistration = this.clientRegistrationRepository.findById(clientRegistration.id()).orElseThrow();
        assertNotEquals("SecretA", clientRegistration.clientSecret());
    }

    private void assertClientRegistrationEquals(ClientRegistrationEntity clientRegistration, JsonNode clientRegistrationNode) {
        assertInstantEquals(clientRegistration.creationTime(), clientRegistrationNode.get("creationTime").textValue());
        assertEquals(clientRegistration.displayName(), clientRegistrationNode.get("displayName").textValue());

        assertJsonArrayContainsExactly(clientRegistrationNode.get("authorizationGrantTypes"), clientRegistration.authorizationGrantTypes());
        assertJsonArrayContainsExactly(clientRegistrationNode.get("redirectUris"), clientRegistration.redirectUris());
    }
}