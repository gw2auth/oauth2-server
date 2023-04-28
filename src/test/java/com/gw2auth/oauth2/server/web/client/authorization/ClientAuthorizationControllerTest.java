package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenWithPreferencesEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.*;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Gw2AuthTestComponentScan
class ClientAuthorizationControllerTest {

    @Autowired
    @RegisterExtension
    TruncateTablesExtension truncateTablesExtension;

    @Autowired
    @RegisterExtension
    Gw2AuthLoginExtension gw2AuthLoginExtension;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestHelper testHelper;

    @Autowired
    private ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;

    @Test
    public void getClientAuthorizationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/authorization/someid"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientAuthorizations(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // create client
        final ApplicationClientEntity client = this.testHelper.createClientRegistration(accountId, "Client");

        // create consent
        this.testHelper.createClientConsent(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE));

        // create 2 authorizations
        final ApplicationClientAuthorizationEntity authorization1 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2()));
        final ApplicationClientAuthorizationEntity authorization2 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE));

        // insert tokens for these authorizations
        final Gw2AccountApiTokenWithPreferencesEntity tokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token A");
        final Gw2AccountApiTokenWithPreferencesEntity tokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token B");
        final Gw2AccountApiTokenWithPreferencesEntity tokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token C");
        final Gw2AccountApiTokenWithPreferencesEntity tokenD = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token D");

        this.testHelper.createClientAuthorizationTokens(accountId, authorization1.id(), tokenA.gw2AccountId(), tokenD.gw2AccountId());
        this.testHelper.createClientAuthorizationTokens(accountId, authorization2.id(), tokenA.gw2AccountId(), tokenB.gw2AccountId(), tokenC.gw2AccountId());

        // query api
        final String jsonResponse = this.mockMvc.perform(get("/api/client/authorization/{clientId}", client.id()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode node = mapper.readTree(jsonResponse);

        assertTrue(node.isArray());
        assertEquals(2, node.size());

        Instant previousCreationTime = Instant.MIN;

        for (int i = 0; i < node.size(); i++) {
            final JsonNode authorizationNode = node.get(i);
            final String id = authorizationNode.get("id").textValue();
            final ApplicationClientAuthorizationEntity authorization;
            final Map<UUID, Gw2AccountApiTokenWithPreferencesEntity> apiTokens;

            if (id.equals(authorization1.id())) {
                authorization = authorization1;
                apiTokens = Map.of(tokenA.gw2AccountId(), tokenA, tokenD.gw2AccountId(), tokenD);
            } else if (id.equals(authorization2.id())) {
                authorization = authorization2;
                apiTokens = Map.of(tokenA.gw2AccountId(), tokenA, tokenB.gw2AccountId(), tokenB, tokenC.gw2AccountId(), tokenC);
            } else {
                fail("unknown authorization id found in response");
                throw new IllegalStateException("");
            }

            assertInstantEquals(authorization.creationTime(), authorizationNode.get("creationTime").textValue());
            assertInstantEquals(authorization.lastUpdateTime(), authorizationNode.get("lastUpdateTime").textValue());
            assertEquals(authorization.displayName(), authorizationNode.get("displayName").textValue());

            final Instant creationTime = Instant.parse(authorizationNode.get("creationTime").textValue());
            assertTrue(previousCreationTime.isBefore(creationTime));
            previousCreationTime = creationTime;

            // authorized scopes
            final Set<String> expectedAuthorizedScopes = new HashSet<>(authorization.authorizedScopes());
            final JsonNode gw2ApiPermissionsNode = authorizationNode.get("authorizedGw2ApiPermissions");
            assertTrue(gw2ApiPermissionsNode.isArray());

            for (int j = 0; j < gw2ApiPermissionsNode.size(); j++) {
                final String gw2ApiPermissionStr = gw2ApiPermissionsNode.get(j).textValue();
                final Gw2ApiPermission gw2ApiPermission = Gw2ApiPermission.fromGw2(gw2ApiPermissionStr).orElseThrow();

                if (!expectedAuthorizedScopes.remove(gw2ApiPermission.oauth2())) {
                    fail("received gw2 api permission which is not present in the entity");
                }
            }

            if (authorizationNode.get("authorizedVerifiedInformation").booleanValue()) {
                if (!expectedAuthorizedScopes.remove(ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE)) {
                    fail("received verified scope but it is not present in the entity");
                }
            }

            assertTrue(expectedAuthorizedScopes.isEmpty());

            // tokens
            final Map<UUID, Gw2AccountApiTokenWithPreferencesEntity> expectedApiTokens = new HashMap<>(apiTokens);
            final JsonNode tokensNode = authorizationNode.get("tokens");
            assertTrue(tokensNode.isArray());

            String previousDisplayName = null;

            for (int j = 0; j < tokensNode.size(); j++) {
                final JsonNode tokenNode = tokensNode.get(j);
                final Gw2AccountApiTokenWithPreferencesEntity expectedApiToken = expectedApiTokens.remove(UUID.fromString(tokenNode.get("gw2AccountId").textValue()));
                final String displayName = tokenNode.get("displayName").textValue();

                assertNotNull(expectedApiToken);
                assertEquals(expectedApiToken.displayName(), displayName);

                if (previousDisplayName != null) {
                    assertTrue(previousDisplayName.compareTo(displayName) <= 0);
                }

                previousDisplayName = displayName;
            }

            assertTrue(expectedApiTokens.isEmpty());
        }
    }

    @Test
    public void deleteClientAuthorizationsUnauthenticated() throws Exception {
        this.mockMvc.perform(delete("/api/client/authorization/someid").with(csrf()))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteClientAuthorization(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // create client
        final ApplicationClientEntity client = this.testHelper.createClientRegistration(accountId, "Client");

        // create consent
        this.testHelper.createClientConsent(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE));

        // create 2 authorizations
        final ApplicationClientAuthorizationEntity authorization1 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2()));
        final ApplicationClientAuthorizationEntity authorization2 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE));

        // insert tokens for these authorizations
        final Gw2AccountApiTokenWithPreferencesEntity tokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token A");
        final Gw2AccountApiTokenWithPreferencesEntity tokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token B");
        final Gw2AccountApiTokenWithPreferencesEntity tokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token C");
        final Gw2AccountApiTokenWithPreferencesEntity tokenD = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token D");

        this.testHelper.createClientAuthorizationTokens(accountId, authorization1.id(), tokenA.gw2AccountId(), tokenD.gw2AccountId());
        this.testHelper.createClientAuthorizationTokens(accountId, authorization2.id(), tokenA.gw2AccountId(), tokenB.gw2AccountId(), tokenC.gw2AccountId());

        // delete second authorization
        this.mockMvc.perform(delete("/api/client/authorization/_/{clientAuthorizationId}", authorization2.id()).with(csrf()).with(sessionHandle))
                .andDo(sessionHandle)
                .andExpect(status().isOk());

        // verify the authorization has been deleted
        assertTrue(this.applicationClientAuthorizationRepository.findByIdAndAccountId(authorization2.id(), accountId).isEmpty());

        // verify the first authorization is still present
        assertTrue(this.applicationClientAuthorizationRepository.findByIdAndAccountId(authorization1.id(), accountId).isPresent());
    }
}