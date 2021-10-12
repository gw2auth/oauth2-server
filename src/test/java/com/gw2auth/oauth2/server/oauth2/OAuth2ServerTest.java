package com.gw2auth.oauth2.server.oauth2;

import com.gw2auth.oauth2.server.Gw2AuthLoginExtension;
import com.gw2auth.oauth2.server.Gw2AuthTestComponentScan;
import com.gw2auth.oauth2.server.TruncateTablesExtension;
import com.gw2auth.oauth2.server.WithGw2AuthLogin;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import org.hamcrest.core.StringContains;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

    @Test
    public void authorizationCodeRequestUnknownClient() throws Exception {
        this.mockMvc.perform(
                get("/oauth2/authorize")
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, "abcdefg")
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
    public void authorizationCodeRequestConsent(MockHttpSession session) throws Exception {
        performAuthorizeWithNewClient(session)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", new StringContains("/oauth2/consent")));
    }

    private ResultActions performAuthorizeWithNewClient(MockHttpSession session) throws Exception {
        final Account account = this.accountService.getOrCreateAccount("test", "test");
        final ClientRegistrationCreation clientRegistration = this.clientRegistrationService.createClientRegistration(account.id(), "Test", Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()), "http://127.0.0.1/callback");

        MockHttpServletRequestBuilder builder = get("/oauth2/authorize");

        if (session != null) {
            builder = builder.session(session);
        }

        return this.mockMvc.perform(
                builder
                        .queryParam(OAuth2ParameterNames.CLIENT_ID, clientRegistration.clientRegistration().clientId())
                        .queryParam(OAuth2ParameterNames.SCOPE, Gw2ApiPermission.ACCOUNT.oauth2())
                        .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                        .queryParam(OAuth2ParameterNames.REDIRECT_URI, clientRegistration.clientRegistration().redirectUri())
                        .queryParam(OAuth2ParameterNames.STATE, UUID.randomUUID().toString())
        );
    }
}
