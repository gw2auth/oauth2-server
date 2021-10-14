package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.*;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

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
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private ClientAuthorizationLogRepository clientAuthorizationLogRepository;

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Test
    public void getClientAuthorizationsUnauthenticated() throws Exception {
        this.mockMvc.perform(get("/api/client/authorization"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientAuthorizations(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));
        final ClientRegistrationEntity clientRegistrationC = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));

        final ApiTokenEntity apiTokenA = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameA"));
        final ApiTokenEntity apiTokenB = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameB"));
        final ApiTokenEntity apiTokenC = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameC"));

        final ClientAuthorizationEntity clientAuthorizationA = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationA.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));
        final ClientAuthorizationEntity clientAuthorizationC = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationC.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.GUILDS.oauth2())));

        // tokens for authorization A
        final ClientAuthorizationTokenEntity authorizationTokenA_A = this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenA.gw2AccountId(), "", Instant.now()));
        final ClientAuthorizationTokenEntity authorizationTokenA_C = this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenC.gw2AccountId(), "", Instant.now()));

        // tokens for authorization C
        final ClientAuthorizationTokenEntity authorizationTokenC_B = this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationC.clientRegistrationId(), apiTokenB.gw2AccountId(), "", Instant.now()));

        final String jsonResponse = this.mockMvc.perform(get("/api/client/authorization").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andReturn()
                .getResponse()
                .getContentAsString();

        final ObjectMapper mapper = new ObjectMapper();
        final JsonNode node = mapper.readTree(jsonResponse);

        assertTrue(node.isArray());

        boolean foundAuthorizationA = false;
        boolean foundAuthorizationC = false;

        for (int i = 0; i < node.size(); i++) {
            final JsonNode element = node.get(i);
            final JsonNode clientRegistrationNode = element.get("clientRegistration");

            final ClientRegistrationEntity clientRegistration;
            final ClientAuthorizationEntity clientAuthorization;
            final Map<String, ApiTokenEntity> apiTokens;
            final Map<String, ClientAuthorizationTokenEntity> authorizationTokens;

            if (clientRegistrationNode.get("clientId").textValue().equals(clientRegistrationA.clientId())) {
                if (foundAuthorizationA) {
                    fail("authorization A appeared at least twice in the response");
                    return;
                } else {
                    foundAuthorizationA = true;

                    clientRegistration = clientRegistrationA;
                    clientAuthorization = clientAuthorizationA;
                    apiTokens = new HashMap<>(Map.of(
                            apiTokenA.gw2AccountId(), apiTokenA,
                            apiTokenC.gw2AccountId(), apiTokenC
                    ));
                    authorizationTokens = new HashMap<>(Map.of(
                            apiTokenA.gw2AccountId(), authorizationTokenA_A,
                            apiTokenC.gw2AccountId(), authorizationTokenA_C
                    ));
                }
            } else if (clientRegistrationNode.get("clientId").textValue().equals(clientRegistrationC.clientId())) {
                if (foundAuthorizationC) {
                    fail("authorization C appeared at least twice in the response");
                    return;
                } else {
                    foundAuthorizationC = true;

                    clientRegistration = clientRegistrationC;
                    clientAuthorization = clientAuthorizationC;
                    apiTokens = new HashMap<>(Map.of(apiTokenB.gw2AccountId(), apiTokenB));
                    authorizationTokens = new HashMap<>(Map.of(apiTokenB.gw2AccountId(), authorizationTokenC_B));
                }
            } else {
                fail("unknown authorization appeared in response");
                return;
            }

            // registration
            assertInstantEquals(clientRegistration.creationTime(), clientRegistrationNode.get("creationTime").textValue());
            assertEquals(clientRegistration.displayName(), clientRegistrationNode.get("displayName").textValue());
            assertEquals(clientRegistration.redirectUri(), clientRegistrationNode.get("redirectUri").textValue());

            // accountsub
            assertEquals(clientAuthorization.accountSub().toString(), element.get("accountSub").textValue());

            // authorized scopes
            final Set<String> expectedScopes = new HashSet<>(clientAuthorization.authorizedScopes());
            final JsonNode authorizedGw2ApiPermissionsNode = element.get("authorizedGw2ApiPermissions");

            assertTrue(authorizedGw2ApiPermissionsNode.isArray());

            for (int j = 0; j < authorizedGw2ApiPermissionsNode.size(); j++) {
                final Gw2ApiPermission gw2ApiPermission = Gw2ApiPermission.fromGw2(authorizedGw2ApiPermissionsNode.get(j).textValue()).orElseThrow();

                if (!expectedScopes.remove(gw2ApiPermission.oauth2())) {
                    fail("got unexpected scope in authorization");
                }
            }

            assertTrue(expectedScopes.isEmpty());

            // tokens
            final JsonNode tokensNode = element.get("tokens");
            assertTrue(tokensNode.isArray());

            for (int j = 0; j < tokensNode.size(); j++) {
                final JsonNode tokenNode = tokensNode.get(j);
                final String gw2AccountId = tokenNode.get("gw2AccountId").textValue();

                final ApiTokenEntity apiToken = apiTokens.remove(gw2AccountId);
                final ClientAuthorizationTokenEntity authorizationToken = authorizationTokens.remove(gw2AccountId);

                assertEquals(apiToken.displayName(), tokenNode.get("displayName").textValue());
                assertInstantEquals(authorizationToken.expirationTime(), tokenNode.get("expirationTime").textValue());
            }

            assertTrue(apiTokens.isEmpty());
            assertTrue(authorizationTokens.isEmpty());
        }
    }

    @Test
    public void getClientAuthorizationLogPageUnauthorized() throws Exception {
        this.mockMvc.perform(get("/api/client/authorization/someid/logs"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void getClientAuthorizationLogPageEmpty(MockHttpSession session) throws Exception {
        this.mockMvc.perform(get("/api/client/authorization/someid/logs").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value("0"))
                .andExpect(jsonPath("$.nextPage").value("-1"))
                .andExpect(jsonPath("$.logs.length()").value("0"));
    }

    @WithGw2AuthLogin
    public void getClientAuthorizationLogPage(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final ClientRegistrationEntity clientRegistration = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));
        final ClientAuthorizationEntity clientAuthorization = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistration.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));

        final Queue<ClientAuthorizationLogEntity> insertedLogs = new PriorityQueue<>(Comparator.comparing(ClientAuthorizationLogEntity::timestamp).reversed());
        Instant timestamp = Instant.now();

        for (int i = 0; i < 143; i++) {
            final int generateMessageCount = ThreadLocalRandom.current().nextInt(20);
            final List<String> messages = new ArrayList<>(generateMessageCount);

            for (int j = 0; j < generateMessageCount; j++) {
                messages.add(UUID.randomUUID().toString());
            }

            insertedLogs.offer(this.clientAuthorizationLogRepository.save(new ClientAuthorizationLogEntity(null, accountId, clientAuthorization.clientRegistrationId(), timestamp, UUID.randomUUID().toString(), messages)));
            timestamp = timestamp.plus(Duration.ofMinutes(12L));
        }

        final ObjectMapper mapper = new ObjectMapper();
        int page = 0;

        do {
            final String responseJson = this.mockMvc.perform(
                    get("/api/client/authorization/{clientId}/logs", clientRegistration.clientId())
                            .session(session)
                            .queryParam("page", Integer.toString(page))
            )
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.page").exists())
                    .andExpect(jsonPath("$.nextPage").exists())
                    .andExpect(jsonPath("$.logs").exists())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();

            final JsonNode responseNode = mapper.readTree(responseJson);
            final int nextPage = responseNode.get("nextPage").intValue();

            assertEquals(page, responseNode.get("page").intValue());
            assertTrue(nextPage == page + 1 || nextPage == -1);

            final JsonNode logsNode = responseNode.get("logs");
            assertTrue(logsNode.isArray());

            for (int i = 0; i < logsNode.size(); i++) {
                final ClientAuthorizationLogEntity expectedLog = insertedLogs.poll();
                assertNotNull(expectedLog);

                final JsonNode logNode = logsNode.get(i);

                assertInstantEquals(expectedLog.timestamp(), logNode.get("timestamp").textValue());
                assertEquals(expectedLog.type(), logNode.get("type").textValue());

                final JsonNode messagesNode = logNode.get("messages");
                assertTrue(messagesNode.isArray());

                for (int j = 0; j < messagesNode.size(); j++) {
                    assertEquals(expectedLog.messages().get(j), messagesNode.get(j).textValue());
                }
            }

            page = nextPage;
        } while (page != -1);

        assertTrue(insertedLogs.isEmpty());
    }

    @Test
    public void deleteClientAuthorizationUnauthorized() throws Exception {
        this.mockMvc.perform(delete("/api/client/authorization/someid"))
                .andExpect(status().isForbidden());
    }

    @WithGw2AuthLogin
    public void deleteClientAuthorization(MockHttpSession session) throws Exception {
        final long accountId = AuthenticationHelper.getUser(session).orElseThrow().getAccountId();

        final ClientRegistrationEntity clientRegistrationA = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));
        final ClientRegistrationEntity clientRegistrationB = this.clientRegistrationRepository.save(new ClientRegistrationEntity(null, accountId, Instant.now(), "Name", UUID.randomUUID().toString(), "", Set.of(), "http://127.0.0.1/"));

        final ApiTokenEntity apiTokenA = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameA"));
        final ApiTokenEntity apiTokenB = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameB"));
        final ApiTokenEntity apiTokenC = this.apiTokenRepository.save(new ApiTokenEntity(accountId, UUID.randomUUID().toString(), Instant.now(), UUID.randomUUID().toString(), Gw2ApiPermission.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), "TokenNameC"));

        final ClientAuthorizationEntity clientAuthorizationA = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationA.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2())));
        final ClientAuthorizationEntity clientAuthorizationB = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(accountId, clientRegistrationB.id(), UUID.randomUUID(), Set.of(Gw2ApiPermission.ACCOUNT.oauth2(), Gw2ApiPermission.GUILDS.oauth2())));

        // tokens for authorization A
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenA.gw2AccountId(), "", Instant.now()));
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationA.clientRegistrationId(), apiTokenC.gw2AccountId(), "", Instant.now()));

        // tokens for authorization B
        this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationB.clientRegistrationId(), apiTokenB.gw2AccountId(), "", Instant.now()));

        // logs for authorization A
        this.clientAuthorizationLogRepository.save(new ClientAuthorizationLogEntity(null, accountId, clientAuthorizationA.clientRegistrationId(), Instant.now(), "SomeTypeA", List.of()));
        this.clientAuthorizationLogRepository.save(new ClientAuthorizationLogEntity(null, accountId, clientAuthorizationA.clientRegistrationId(), Instant.now(), "SomeTypeA", List.of()));

        // logs for authorization B
        this.clientAuthorizationLogRepository.save(new ClientAuthorizationLogEntity(null, accountId, clientAuthorizationB.clientRegistrationId(), Instant.now(), "SomeTypeB", List.of()));

        // delete authorization A
        this.mockMvc.perform(delete("/api/client/authorization/{clientId}", clientRegistrationA.clientId()).session(session).with(csrf()))
                .andExpect(status().isOk());

        // entity should still be there
        ClientAuthorizationEntity clientAuthorization = this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientAuthorizationA.clientRegistrationId()).orElse(null);
        assertNotNull(clientAuthorization);
        assertNotEquals(clientAuthorizationA, clientAuthorization);
        assertTrue(clientAuthorization.authorizedScopes().isEmpty());
        assertEquals(clientAuthorizationA.accountSub(), clientAuthorization.accountSub());

        // logs and tokens should be deleted
        assertTrue(this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientAuthorizationA.clientRegistrationId()).isEmpty());
        assertTrue(this.clientAuthorizationLogRepository.findByAccountIdAndClientId(accountId, clientRegistrationA.clientId(), 0, 10).findAny().isEmpty());

        // authorization B should still be there (and unchanged)
        clientAuthorization = this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientAuthorizationB.clientRegistrationId()).orElse(null);
        assertEquals(clientAuthorizationB, clientAuthorization);

        // logs and tokens of B should still be there
        assertEquals(1, this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientAuthorizationB.clientRegistrationId()).size());
        assertEquals(1L, this.clientAuthorizationLogRepository.findByAccountIdAndClientId(accountId, clientRegistrationB.clientId(), 0, 10).count());
    }
}