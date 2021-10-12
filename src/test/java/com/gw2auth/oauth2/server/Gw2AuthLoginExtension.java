package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.configuration.OAuth2ClientConfiguration;
import com.gw2auth.oauth2.server.util.Utils;
import org.hamcrest.core.IsNot;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.lang.reflect.Method;
import java.net.URL;
import java.util.Objects;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Component
public class Gw2AuthLoginExtension implements BeforeEachCallback, AfterEachCallback {

    public static final ExtensionContext.Namespace NAMESPACE = ExtensionContext.Namespace.create(Gw2AuthLoginExtension.class);

    private final MockMvc mockMvc;
    private final OAuth2ClientConfiguration.TestClientRegistrationRepository testClientRegistrationRepository;

    @Autowired
    public Gw2AuthLoginExtension(MockMvc mockMvc, OAuth2ClientConfiguration.TestClientRegistrationRepository testClientRegistrationRepository) {
        this.mockMvc = mockMvc;
        this.testClientRegistrationRepository = testClientRegistrationRepository;
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        final Method method = context.getTestMethod().orElse(null);

        if (method != null) {
            final WithGw2AuthLogin gw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);

            if (gw2AuthLogin != null) {
                final MockHttpSession session = context.getStore(NAMESPACE).getOrComputeIfAbsent("session", (k) -> new MockHttpSession(), MockHttpSession.class);

                this.testClientRegistrationRepository.prepareRegistrationId(gw2AuthLogin.issuer());

                final MvcResult result = this.mockMvc.perform(get("/oauth2/authorization/" + gw2AuthLogin.issuer()).session(session)).andReturn();
                final String location = Objects.requireNonNull(result.getResponse().getHeader("Location"));
                final String state = Utils.parseQuery(new URL(location).getQuery())
                        .filter((pair) -> pair[0].equals("state"))
                        .map((pair) -> pair[1])
                        .findFirst()
                        .orElseThrow();

                this.mockMvc.perform(
                        get("/login/oauth2/code/" + gw2AuthLogin.issuer())
                                .session(session)
                                .queryParam("code", gw2AuthLogin.idAtIssuer())
                                .queryParam("state", state)
                )
                        .andExpect(status().is3xxRedirection())
                        .andExpect(header().string("Location", new IsNot<>(new StringEndsWith("?error"))));
            }
        }
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        final Method method = context.getTestMethod().orElse(null);

        if (method != null) {
            final WithGw2AuthLogin gw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);

            if (gw2AuthLogin != null) {
                final MockHttpSession session = context.getStore(NAMESPACE).get("session", MockHttpSession.class);

                this.mockMvc.perform(post("/logout").session(session).with(csrf()))
                        .andExpect(status().isOk());

                context.getStore(NAMESPACE).remove("session", MockHttpSession.class);
            }
        }
    }
}
