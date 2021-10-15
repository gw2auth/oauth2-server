package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.configuration.OAuth2ClientConfiguration;
import com.gw2auth.oauth2.server.util.QueryParam;
import com.gw2auth.oauth2.server.util.Utils;
import org.hamcrest.core.IsNot;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
    private ExtensionContext context;

    @Autowired
    public Gw2AuthLoginExtension(MockMvc mockMvc, OAuth2ClientConfiguration.TestClientRegistrationRepository testClientRegistrationRepository) {
        this.mockMvc = mockMvc;
        this.testClientRegistrationRepository = testClientRegistrationRepository;
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        this.context = context;

        final Method method = context.getTestMethod().orElse(null);

        if (method != null) {
            final WithGw2AuthLogin gw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);

            if (gw2AuthLogin != null) {
                loginInternal(context, gw2AuthLogin.issuer(), gw2AuthLogin.idAtIssuer()).andExpectAll(expectSuccess());
            }
        }
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        this.context = null;

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

    public ResultMatcher[] expectSuccess() {
        return new ResultMatcher[]{
                status().is3xxRedirection(),
                header().string("Location", new IsNot<>(new StringEndsWith("?error")))
        };
    }

    public ResultActions login(String issuer, String idAtIssuer) throws Exception {
        return loginInternal(this.context, issuer, idAtIssuer);
    }

    public ResultActions login(String loginUrl, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(this.context, loginUrl, issuer, idAtIssuer);
    }

    private ResultActions loginInternal(ExtensionContext context, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(context, "/oauth2/authorization/" + URLEncoder.encode(issuer, StandardCharsets.UTF_8), issuer, idAtIssuer);
    }

    private ResultActions loginInternal(ExtensionContext context, String loginURL, String issuer, String idAtIssuer) throws Exception {
        final MockHttpSession session = context.getStore(NAMESPACE).getOrComputeIfAbsent("session", (k) -> new MockHttpSession(), MockHttpSession.class);

        this.testClientRegistrationRepository.prepareRegistrationId(issuer);

        final MvcResult result = this.mockMvc.perform(get(loginURL).session(session)).andReturn();
        final String location = Objects.requireNonNull(result.getResponse().getHeader("Location"));
        final String state = Utils.parseQuery(new URL(location).getQuery())
                .filter(QueryParam::hasValue)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.STATE))
                .map(QueryParam::value)
                .findFirst()
                .orElseThrow();

        return this.mockMvc.perform(
                get("/login/oauth2/code/{issuer}", issuer)
                        .session(session)
                        .queryParam("code", idAtIssuer)
                        .queryParam("state", state)
        );
    }
}
