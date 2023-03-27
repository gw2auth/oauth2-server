package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class ClientConsentControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ClientConsentRepository clientConsentRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getClientConsentsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/consent"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientConsents(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final ClientRegistrationEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "Name");
        final ClientRegistrationEntity clientRegistrationC = this.testHelper.createClientRegistration(accountId, "Name");

        final ClientConsentEntity clientConsentA = this.testHelper.createClientConsent(accountId, clientRegistrationA.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), ClientConsentService.GW2AUTH_VERIFIED_SCOPE));
        final ClientConsentEntity clientConsentB = this.testHelper.createClientConsent(accountId, clientRegistrationC.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.GUILDS.oauth2()));

        final String jsonResponse = this.mockMvc.perform(get("/api/client/consent").with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode node = mapper.readTree(jsonResponse);

        assertTrue(node.isArray());

        String previousRegistrationDisplayName = null;
        boolean foundAuthorizationA = false;
        boolean foundAuthorizationC = false;

        for (int i = 0; i < node.size(); i++) {
            final JsonNode element = node.get(i);
            final JsonNode clientRegistrationNode = element.get("clientRegistration");

            final ClientRegistrationEntity clientRegistration;
            final ClientConsentEntity clientConsent;

            if (clientRegistrationNode.get("clientId").textValue().equals(clientRegistrationA.id().toString())) {
                if (foundAuthorizationA) {
                    fail("authorization A appeared at least twice in the response");
                    return;
                } else {
                    foundAuthorizationA = true;

                    clientRegistration = clientRegistrationA;
                    clientConsent = clientConsentA;
                }
            } else if (clientRegistrationNode.get("clientId").textValue().equals(clientRegistrationC.id().toString())) {
                if (foundAuthorizationC) {
                    fail("authorization C appeared at least twice in the response");
                    return;
                } else {
                    foundAuthorizationC = true;

                    clientRegistration = clientRegistrationC;
                    clientConsent = clientConsentB;
                }
            } else {
                fail("unknown authorization appeared in response");
                return;
            }

            // registration
            final String registrationDisplayName = clientRegistrationNode.get("displayName").textValue();
            assertInstantEquals(clientRegistration.creationTime(), clientRegistrationNode.get("creationTime").textValue());
            assertEquals(clientRegistration.displayName(), registrationDisplayName);

            if (previousRegistrationDisplayName != null) {
                assertTrue(previousRegistrationDisplayName.compareTo(registrationDisplayName) <= 0);
            }

            previousRegistrationDisplayName = registrationDisplayName;

            // accountsub
            assertEquals(clientConsent.accountSub().toString(), element.get("accountSub").textValue());

            // authorized scopes
            final Set<String> expectedScopes = new HashSet<>(clientConsent.authorizedScopes());
            final JsonNode authorizedGw2ApiPermissionsNode = element.get("authorizedGw2ApiPermissions");

            assertTrue(authorizedGw2ApiPermissionsNode.isArray());

            for (int j = 0; j < authorizedGw2ApiPermissionsNode.size(); j++) {
                final Gw2ApiPermission gw2ApiPermission = Gw2ApiPermission.fromGw2(authorizedGw2ApiPermissionsNode.get(j).textValue()).orElseThrow();

                if (!expectedScopes.remove(gw2ApiPermission.oauth2())) {
                    fail("got unexpected scope in authorization");
                }
            }

            if (element.get("authorizedVerifiedInformation").booleanValue()) {
                if (!expectedScopes.remove(ClientConsentService.GW2AUTH_VERIFIED_SCOPE)) {
                    fail("got unexpected scope in authorization");
                }
            }

            assertTrue(expectedScopes.isEmpty());
        }

        assertTrue(foundAuthorizationA);
        assertTrue(foundAuthorizationC);
    }

    @Test
    public void deleteClientConsentUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/client/consent/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteClientConsent(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final ClientRegistrationEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "Name");
        final ClientRegistrationEntity clientRegistrationB = this.testHelper.createClientRegistration(accountId, "Name");

        final ApiTokenEntity apiTokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameA");
        final ApiTokenEntity apiTokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameB");
        final ApiTokenEntity apiTokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameC");

        final ClientConsentEntity clientConsentA = this.testHelper.createClientConsent(accountId, clientRegistrationA.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2()));
        final ClientConsentEntity clientConsentB = this.testHelper.createClientConsent(accountId, clientRegistrationB.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.GUILDS.oauth2()));

        final String authorizationIdA = this.testHelper.createClientAuthorization(accountId, clientConsentA.clientRegistrationId(), clientConsentA.authorizedScopes()).id();
        final String authorizationIdB = this.testHelper.createClientAuthorization(accountId, clientConsentB.clientRegistrationId(), clientConsentB.authorizedScopes()).id();

        // tokens for authorization A
        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdA, apiTokenA.gw2AccountId(), apiTokenC.gw2AccountId());

        // tokens for authorization B
        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdB, apiTokenB.gw2AccountId());

        // delete authorization A
        this.mockMvc.perform(delete("/api/client/consent/{clientId}", clientRegistrationA.id()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // entity should still be there
        ClientConsentEntity clientConsent = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientConsentA.clientRegistrationId()).orElse(null);
        assertNotNull(clientConsent);
        assertNotEquals(clientConsentA, clientConsent);
        assertTrue(clientConsent.authorizedScopes().isEmpty());
        assertEquals(clientConsentA.accountSub(), clientConsent.accountSub());

        // tokens should be deleted
        assertTrue(this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, authorizationIdA).isEmpty());

        // authorization B should still be there (and unchanged)
        clientConsent = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientConsentB.clientRegistrationId()).orElse(null);
        assertEquals(clientConsentB, clientConsent);

        // tokens of B should still be there
        assertEquals(1, this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, authorizationIdB).size());
    }
}