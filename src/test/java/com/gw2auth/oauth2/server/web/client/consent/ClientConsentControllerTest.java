package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.util.Pair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;
import java.util.UUID;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Assertions.assertJsonArrayContainsExactly;
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
    private ApplicationClientAccountRepository applicationClientAccountRepository;

    @Autowired
    private ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;

    @Autowired
    private ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository;

    @Autowired
    private TestHelper testHelper;

    @Test
    public void getClientConsentsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/consent"))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientConsents(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final ApplicationClientEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "Name");
        final ApplicationClientEntity clientRegistrationC = this.testHelper.createClientRegistration(accountId, "Name");

        final Pair<UUID, ApplicationClientAccountEntity> clientConsentA = this.testHelper.createClientConsent2(accountId, clientRegistrationA.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED));
        final Pair<UUID, ApplicationClientAccountEntity> clientConsentB = this.testHelper.createClientConsent2(accountId, clientRegistrationC.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_GUILDS));

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

            final ApplicationClientEntity clientRegistration;
            final Pair<UUID, ApplicationClientAccountEntity> clientConsent;

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
            assertEquals(clientConsent.v1().toString(), element.get("accountSub").textValue());

            // authorized scopes
            final JsonNode authorizedScopesNode = element.get("authorizedScopes");
            assertJsonArrayContainsExactly(authorizedScopesNode, clientConsent.v2().authorizedScopes());
        }

        assertTrue(foundAuthorizationA);
        assertTrue(foundAuthorizationC);
    }

    @Test
    public void deleteClientConsentUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/client/consent/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteClientConsent(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        final ApplicationClientEntity clientRegistrationA = this.testHelper.createClientRegistration(accountId, "Name");
        final ApplicationClientEntity clientRegistrationB = this.testHelper.createClientRegistration(accountId, "Name");

        final Gw2AccountApiTokenEntity apiTokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameA").v2();
        final Gw2AccountApiTokenEntity apiTokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameB").v2();
        final Gw2AccountApiTokenEntity apiTokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "TokenNameC").v2();

        final ApplicationClientAccountEntity clientConsentA = this.testHelper.createClientConsent(accountId, clientRegistrationA.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));
        final ApplicationClientAccountEntity clientConsentB = this.testHelper.createClientConsent(accountId, clientRegistrationB.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2_GUILDS));

        final String authorizationIdA = this.testHelper.createClientAuthorization(accountId, clientConsentA).id();
        final String authorizationIdB = this.testHelper.createClientAuthorization(accountId, clientConsentB).id();

        // tokens for authorization A
        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdA, apiTokenA.gw2AccountId(), apiTokenC.gw2AccountId());

        // tokens for authorization B
        this.testHelper.createClientAuthorizationTokens(accountId, authorizationIdB, apiTokenB.gw2AccountId());

        // delete consent A
        this.mockMvc.perform(delete("/api/client/consent/{clientId}", clientRegistrationA.id()).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // entity should still be there
        ApplicationClientAccountEntity applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                clientConsentA.applicationClientId(),
                accountId
        ).orElse(null);
        assertNotNull(applicationClientAccountEntity);
        assertNotEquals(clientConsentA, applicationClientAccountEntity);
        assertTrue(applicationClientAccountEntity.authorizedScopes().isEmpty());

        // authorization should be deleted
        assertTrue(this.applicationClientAuthorizationRepository.findByIdAndAccountId(authorizationIdA, accountId).isEmpty());

        // tokens should be deleted
        assertTrue(this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(authorizationIdA, accountId).isEmpty());

        // consent B should still be there (and unchanged)
        applicationClientAccountEntity = this.applicationClientAccountRepository.findByApplicationClientIdAndAccountId(
                clientConsentB.applicationClientId(),
                accountId
        ).orElse(null);
        assertEquals(clientConsentB, applicationClientAccountEntity);

        // authorization should still be there
        assertTrue(this.applicationClientAuthorizationRepository.findByIdAndAccountId(authorizationIdB, accountId).isPresent());

        // tokens of B should still be there
        assertEquals(1, this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(authorizationIdB, accountId).size());
    }
}