package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

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

    @Test
    public void getClientRegistrationsUnauthorized() throws Exception {
        this.mockMvc.perform(get("/api/client/registration"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientRegistrationsEmpty(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/client/registration").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("0"));
    }

    @WithGw2AuthLogin
    public void getClientRegistrations(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "NameA", UUID.randomUUID().toString(), "SecretA", Set.of(), "http://127.0.0.1/a"));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "NameB", UUID.randomUUID().toString(), "SecretB", Set.of(), "http://127.0.0.1/b"));

        final String responseJson = this.mockMvc.perform(get("/api/client/registration").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value("2"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode responseNode = mapper.readTree(responseJson);
        assertTrue(responseNode.isArray());

        boolean foundA = false;
        boolean foundB = false;

        for (int i = 0; i < responseNode.size(); i++) {
            final JsonNode clientRegistrationNode = responseNode.get(i);
            final String clientId = clientRegistrationNode.get("clientId").textValue();
            final ClientRegistrationEntity clientRegistration;

            if (clientId.equals(clientRegistrationA.clientId())) {
                if (foundA) {
                    fail("Received A twice");
                    return;
                } else {
                    foundA = true;
                    clientRegistration = clientRegistrationA;
                }
            } else if (clientId.equals(clientRegistrationB.clientId())) {
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
        }
    }

    @Test
    public void getClientRegistrationUnauthorized() throws Exception {
        this.mockMvc.perform(get("/api/client/registration/someid"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientRegistrationOfOtherUser(MockHttpSession session) throws Exception {
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, otherUserAccountId, Instant.now(), "NameA", UUID.randomUUID().toString(), "SecretA", Set.of(), "http://127.0.0.1/a"));

        this.mockMvc.perform(get("/api/client/registration/{clientId}", clientRegistration.clientId()).session(session))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void getClientRegistrationNotExisting(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/client/registration/someid").session(session))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void getClientRegistration(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "NameA", UUID.randomUUID().toString(), "SecretA", Set.of(), "http://127.0.0.1/a"));

        this.mockMvc.perform(get("/api/client/registration/{clientId}", clientRegistration.clientId()).session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creationTime").value(clientRegistration.creationTime().toString()))
                .andExpect(jsonPath("$.displayName").value(clientRegistration.displayName()))
                .andExpect(jsonPath("$.redirectUri").value(clientRegistration.redirectUri()))
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes.length()").value("0"));
    }

    @Test
    public void deleteClientRegistrationUnauthorized() throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistrationOfOtherUser(MockHttpSession session) throws Exception {
        final long otherUserAccountId = this.accountRepository.save(new AccountEntity(null, Instant.now())).id();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, otherUserAccountId, Instant.now(), "NameA", UUID.randomUUID().toString(), "SecretA", Set.of(), "http://127.0.0.1/a"));

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", clientRegistration.clientId()).session(session).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistrationNotExisting(MockHttpSession session) throws Exception {
        this.mockMvc.perform(delete("/api/client/registration/someid").session(session).with(csrf()))
                .andExpect(status().isNotFound());
    }

    @WithGw2AuthLogin
    public void deleteClientRegistration(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();
        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "NameA", UUID.randomUUID().toString(), "SecretA", Set.of(), "http://127.0.0.1/a"));

        this.mockMvc.perform(delete("/api/client/registration/{clientId}", clientRegistration.clientId()).session(session).with(csrf()))
                .andExpect(status().isOk());

        assertTrue(this.clientRegistrationRepository.findByClientId(clientRegistration.clientId()).isEmpty());
    }

    @Test
    public void createClientRegistrationUnauthorized() throws Exception {
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
    public void createClientRegistrationMissingParameters(MockHttpSession session) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .session(session)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test"}
                        """)
                )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void createClientRegistrationInvalidRedirectURI(MockHttpSession session) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .session(session)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUri": "http://localhost/"}
                        """)
                )
                .andExpect(status().isBadRequest());
    }

    @WithGw2AuthLogin
    public void createClientRegistration(MockHttpSession session) throws Exception {
        this.mockMvc.perform(
                        post("/api/client/registration")
                                .session(session)
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                        {"displayName": "Test", "authorizationGrantTypes": ["authorization_code"], "redirectUri": "http://127.0.0.1/a/b/c"}
                        """)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientSecret").isString())
                .andExpect(jsonPath("$.clientRegistration.creationTime").isString())
                .andExpect(jsonPath("$.clientRegistration.displayName").value("Test"))
                .andExpect(jsonPath("$.clientRegistration.clientId").isString())
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes.length()").value("1"))
                .andExpect(jsonPath("$.clientRegistration.authorizationGrantTypes[0]").value("authorization_code"))
                .andExpect(jsonPath("$.clientRegistration.redirectUri").value("http://127.0.0.1/a/b/c"));

        assertEquals(1, this.clientRegistrationRepository.findAllByAccountId(AuthenticationHelper.getUser(session).orElseThrow().getAccountId()).size());
    }

    private void assertClientRegistrationEquals(ClientRegistrationEntity clientRegistration, JsonNode clientRegistrationNode) {
        assertEquals(clientRegistration.creationTime().toString(), clientRegistrationNode.get("creationTime").textValue());
        assertEquals(clientRegistration.displayName(), clientRegistrationNode.get("displayName").textValue());
        assertEquals(clientRegistration.redirectUri(), clientRegistrationNode.get("redirectUri").textValue());

        final Set<String> expectedGrantTypes = new HashSet<>(clientRegistration.authorizationGrantTypes());
        final JsonNode grantTypesNode = clientRegistrationNode.get("authorizationGrantTypes");
        assertTrue(grantTypesNode.isArray());

        for (int j = 0; j < grantTypesNode.size(); j++) {
            if (!expectedGrantTypes.remove(grantTypesNode.get(j).textValue())) {
                fail("Received unexpected authorizationGrantType");
            }
        }

        assertTrue(expectedGrantTypes.isEmpty());
    }
}