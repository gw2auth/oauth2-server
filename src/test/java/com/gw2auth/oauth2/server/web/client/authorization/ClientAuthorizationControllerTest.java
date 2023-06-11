package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.*;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
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

import java.time.Instant;
import java.util.*;

import static com.gw2auth.oauth2.server.Assertions.assertInstantEquals;
import static com.gw2auth.oauth2.server.Assertions.assertJsonArrayContainsExactly;
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

    @ParameterizedTest
    @WithGw2AuthLogin
    public void getClientAuthorizations(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // create client
        final ApplicationClientEntity client = this.testHelper.createClientRegistration(accountId, "Client");

        // create consent
        this.testHelper.createClientConsent(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED));

        // create 2 authorizations
        final ApplicationClientAuthorizationEntity authorization1 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));
        final ApplicationClientAuthorizationEntity authorization2 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED));

        // insert tokens for these authorizations
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> tokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token A");
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> tokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token B");
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> tokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token C");
        final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> tokenD = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token D");

        this.testHelper.createClientAuthorizationTokens(accountId, authorization1.id(), tokenA.v1().gw2AccountId(), tokenD.v1().gw2AccountId());
        this.testHelper.createClientAuthorizationTokens(accountId, authorization2.id(), tokenA.v1().gw2AccountId(), tokenB.v1().gw2AccountId(), tokenC.v1().gw2AccountId());

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
            final Map<UUID, Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity>> apiTokens;

            if (id.equals(authorization1.id())) {
                authorization = authorization1;
                apiTokens = Map.of(
                        tokenA.v1().gw2AccountId(), tokenA,
                        tokenD.v1().gw2AccountId(), tokenD
                );
            } else if (id.equals(authorization2.id())) {
                authorization = authorization2;
                apiTokens = Map.of(
                        tokenA.v1().gw2AccountId(), tokenA,
                        tokenB.v1().gw2AccountId(), tokenB,
                        tokenC.v1().gw2AccountId(), tokenC
                );
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
            final JsonNode authorizedScopesNode = authorizationNode.get("authorizedScopes");
            assertJsonArrayContainsExactly(authorizedScopesNode, authorization.authorizedScopes());

            // tokens
            final Map<UUID, Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity>> expectedApiTokens = new HashMap<>(apiTokens);
            final JsonNode tokensNode = authorizationNode.get("tokens");
            assertTrue(tokensNode.isArray());

            String previousDisplayName = null;

            for (int j = 0; j < tokensNode.size(); j++) {
                final JsonNode tokenNode = tokensNode.get(j);
                final Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> expectedApiToken = expectedApiTokens.remove(UUID.fromString(tokenNode.get("gw2AccountId").textValue()));
                final String displayName = tokenNode.get("displayName").textValue();

                assertNotNull(expectedApiToken);
                assertEquals(expectedApiToken.v1().displayName(), displayName);

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

    @ParameterizedTest
    @WithGw2AuthLogin
    public void deleteClientAuthorization(SessionHandle sessionHandle) throws Exception {
        final UUID accountId = this.testHelper.getAccountIdForCookie(sessionHandle).orElseThrow();

        // create client
        final ApplicationClientEntity client = this.testHelper.createClientRegistration(accountId, "Client");

        // create consent
        this.testHelper.createClientConsent(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED));

        // create 2 authorizations
        final ApplicationClientAuthorizationEntity authorization1 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT));
        final ApplicationClientAuthorizationEntity authorization2 = this.testHelper.createClientAuthorization(accountId, client.id(), Set.of(OAuth2Scope.GW2_ACCOUNT, OAuth2Scope.GW2AUTH_VERIFIED));

        // insert tokens for these authorizations
        final Gw2AccountApiTokenEntity tokenA = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token A").v2();
        final Gw2AccountApiTokenEntity tokenB = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token B").v2();
        final Gw2AccountApiTokenEntity tokenC = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token C").v2();
        final Gw2AccountApiTokenEntity tokenD = this.testHelper.createApiToken(accountId, UUID.randomUUID(), Gw2ApiPermission.all(), "Token D").v2();

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