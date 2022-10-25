package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.configuration.OAuth2ClientConfiguration;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.QueryParam;
import com.gw2auth.oauth2.server.util.Utils;
import org.hamcrest.Matchers;
import org.hamcrest.core.IsNot;
import org.hamcrest.core.StringEndsWith;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

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
                final CookieHolder cookieHolder = this.context.getStore(NAMESPACE).getOrComputeIfAbsent("cookies", k -> new CookieHolder(), CookieHolder.class);
                loginInternal(cookieHolder, gw2AuthLogin.issuer(), gw2AuthLogin.idAtIssuer()).andExpectAll(expectLoginSuccess());
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
                final CookieHolder cookieHolder = Objects.requireNonNull(context.getStore(NAMESPACE).get("cookies", CookieHolder.class));

                logout(cookieHolder).andExpectAll(expectLogoutSuccess());

                context.getStore(NAMESPACE).remove("cookies", CookieHolder.class);
            }
        }
    }

    public ResultMatcher[] expectLoginSuccess() {
        return new ResultMatcher[]{
                status().is3xxRedirection(),
                header().string("Location", new IsNot<>(new StringEndsWith("?error"))),
                MockMvcResultMatchers.cookie().exists(Constants.ACCESS_TOKEN_COOKIE_NAME),
                MockMvcResultMatchers.cookie().httpOnly(Constants.ACCESS_TOKEN_COOKIE_NAME, true),
                MockMvcResultMatchers.cookie().maxAge(Constants.ACCESS_TOKEN_COOKIE_NAME, Matchers.greaterThan(0))
        };
    }

    public ResultMatcher[] expectLogoutSuccess() {
        return new ResultMatcher[]{
                status().isOk(),
                MockMvcResultMatchers.cookie().exists(Constants.ACCESS_TOKEN_COOKIE_NAME),
                MockMvcResultMatchers.cookie().maxAge(Constants.ACCESS_TOKEN_COOKIE_NAME, 0)
        };
    }

    public ResultActions login(String issuer, String idAtIssuer) throws Exception {
        final CookieHolder cookieHolder = this.context.getStore(NAMESPACE).getOrComputeIfAbsent("cookies", k -> new CookieHolder(), CookieHolder.class);
        return login(cookieHolder, issuer, idAtIssuer);
    }

    public ResultActions login(CookieHolder cookieHolder, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(cookieHolder, issuer, idAtIssuer);
    }

    public ResultActions login(String loginUrl, String issuer, String idAtIssuer) throws Exception {
        final CookieHolder cookieHolder = this.context.getStore(NAMESPACE).getOrComputeIfAbsent("cookies", k -> new CookieHolder(), CookieHolder.class);
        return loginInternal(cookieHolder, loginUrl, issuer, idAtIssuer);
    }

    private ResultActions loginInternal(CookieHolder cookieHolder, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(cookieHolder, "/auth/oauth2/authorization/" + URLEncoder.encode(issuer, StandardCharsets.UTF_8), issuer, idAtIssuer);
    }

    private ResultActions loginInternal(CookieHolder cookieHolder, String loginURL, String issuer, String idAtIssuer) throws Exception {
        this.testClientRegistrationRepository.prepareRegistrationId(issuer);

        final MvcResult result = this.mockMvc.perform(get(loginURL).with(cookieHolder))
                .andDo(cookieHolder)
                .andReturn();

        final String location = Objects.requireNonNull(result.getResponse().getRedirectedUrl());
        final String state = Utils.parseQuery(new URL(location).getQuery())
                .filter(QueryParam::hasValue)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.STATE))
                .map(QueryParam::value)
                .findFirst()
                .orElseThrow();

        return this.mockMvc.perform(
                get("/auth/oauth2/code/{issuer}", issuer)
                        .with(cookieHolder)
                        .queryParam("code", idAtIssuer)
                        .queryParam("state", state)
        ).andDo(cookieHolder);
    }

    public ResultActions logout() throws Exception {
        final CookieHolder cookieHolder = context.getStore(NAMESPACE).get("cookies", CookieHolder.class);
        if (cookieHolder == null) {
            throw new IllegalStateException("not logged in via extension");
        }

        return logout(cookieHolder);
    }

    public ResultActions logout(CookieHolder cookieHolder) throws Exception {
        return this.mockMvc.perform(post("/auth/logout").with(cookieHolder).with(csrf()))
                .andDo(cookieHolder);
    }
}
