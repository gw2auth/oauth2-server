package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.configuration.TestClientRegistrationRepository;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.QueryParam;
import com.gw2auth.oauth2.server.util.Utils;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeMatcher;
import org.hamcrest.core.IsNot;
import org.hamcrest.core.StringEndsWith;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.lang.reflect.Method;
import java.net.URI;
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
    private final TestClientRegistrationRepository testClientRegistrationRepository;
    private final Gw2AuthInternalJwtConverter jwtConverter;
    private @Nullable ExtensionContext context;

    @Autowired
    public Gw2AuthLoginExtension(MockMvc mockMvc, TestClientRegistrationRepository testClientRegistrationRepository, Gw2AuthInternalJwtConverter jwtConverter) {
        this.mockMvc = mockMvc;
        this.testClientRegistrationRepository = testClientRegistrationRepository;
        this.jwtConverter = jwtConverter;
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        this.context = context;

        final Method method = context.getTestMethod().orElse(null);

        if (method != null) {
            final WithGw2AuthLogin gw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);

            if (gw2AuthLogin != null) {
                final SessionHandle sessionHandle = this.context.getStore(NAMESPACE).get("cookies", SessionHandle.class);
                sessionHandle.setCountryCode(gw2AuthLogin.countryCode());
                sessionHandle.setCity(gw2AuthLogin.city());
                sessionHandle.setLatitude(gw2AuthLogin.latitude());
                sessionHandle.setLongitude(gw2AuthLogin.longitude());

                loginInternal(sessionHandle, gw2AuthLogin.issuer(), gw2AuthLogin.idAtIssuer()).andExpectAll(expectLoginSuccess());
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
                final SessionHandle sessionHandle = Objects.requireNonNull(context.getStore(NAMESPACE).get("cookies", SessionHandle.class));

                logout(sessionHandle).andExpectAll(expectLogoutSuccess());

                context.getStore(NAMESPACE).remove("cookies", SessionHandle.class);
            }
        }
    }

    public ResultMatcher[] expectLoginSuccess() {
        return new ResultMatcher[]{
                status().is3xxRedirection(),
                header().string("Location", new IsNot<>(new StringEndsWith("?error"))),
                MockMvcResultMatchers.cookie().exists(Constants.ACCESS_TOKEN_COOKIE_NAME),
                MockMvcResultMatchers.cookie().value(Constants.ACCESS_TOKEN_COOKIE_NAME, accessTokenMatcher()),
                MockMvcResultMatchers.cookie().httpOnly(Constants.ACCESS_TOKEN_COOKIE_NAME, true),
                MockMvcResultMatchers.cookie().maxAge(Constants.ACCESS_TOKEN_COOKIE_NAME, Matchers.greaterThan(0))
        };
    }

    private Matcher<String> accessTokenMatcher() {
        return new TypeSafeMatcher<>() {
            @Override
            protected boolean matchesSafely(String item) {
                final Jwt jwt;
                try {
                    jwt = Gw2AuthLoginExtension.this.jwtConverter.readJWT(item);
                } catch (Exception e) {
                    return false;
                }

                final String sessionId = Gw2AuthLoginExtension.this.jwtConverter.readSessionId(jwt);
                final byte[] encryptionKey = Gw2AuthLoginExtension.this.jwtConverter.readEncryptionKey(jwt);

                return sessionId != null && encryptionKey != null;
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("jwt doesnt match expectations");
            }
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
        final SessionHandle sessionHandle = this.context.getStore(NAMESPACE).getOrComputeIfAbsent("cookies", k -> new SessionHandle(), SessionHandle.class);
        return login(sessionHandle, issuer, idAtIssuer);
    }

    public ResultActions login(SessionHandle sessionHandle, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(sessionHandle, issuer, idAtIssuer);
    }

    public ResultActions login(String loginUrl, String issuer, String idAtIssuer) throws Exception {
        final SessionHandle sessionHandle = this.context.getStore(NAMESPACE).getOrComputeIfAbsent("cookies", k -> new SessionHandle(), SessionHandle.class);
        return loginInternal(sessionHandle, loginUrl, issuer, idAtIssuer);
    }

    private ResultActions loginInternal(SessionHandle sessionHandle, String issuer, String idAtIssuer) throws Exception {
        return loginInternal(sessionHandle, "/auth/oauth2/authorization/" + URLEncoder.encode(issuer, StandardCharsets.UTF_8), issuer, idAtIssuer);
    }

    private ResultActions loginInternal(SessionHandle sessionHandle, String loginURL, String issuer, String idAtIssuer) throws Exception {
        this.testClientRegistrationRepository.prepareRegistrationId(issuer);

        final MvcResult result = this.mockMvc.perform(get(loginURL).with(sessionHandle))
                .andDo(sessionHandle)
                .andReturn();

        final String location = Objects.requireNonNull(result.getResponse().getRedirectedUrl());
        final String state = Utils.parseQuery(new URI(location).parseServerAuthority().getRawQuery())
                .map(queryParam -> queryParam instanceof QueryParam.QueryParamWithValue qpwv ? qpwv : null)
                .filter(Objects::nonNull)
                .filter((queryParam) -> queryParam.name().equals(OAuth2ParameterNames.STATE))
                .map(QueryParam.QueryParamWithValue::value)
                .findFirst()
                .orElseThrow();

        return this.mockMvc.perform(
                get("/auth/oauth2/code/{issuer}", issuer)
                        .with(sessionHandle)
                        .queryParam("code", idAtIssuer)
                        .queryParam("state", state)
        ).andDo(sessionHandle);
    }

    public ResultActions logout() throws Exception {
        final SessionHandle sessionHandle = context.getStore(NAMESPACE).get("cookies", SessionHandle.class);
        if (sessionHandle == null) {
            throw new IllegalStateException("not logged in via extension");
        }

        return logout(sessionHandle);
    }

    public ResultActions logout(SessionHandle sessionHandle) throws Exception {
        return this.mockMvc.perform(post(Constants.LOGOUT_URL).with(sessionHandle).with(csrf()))
                .andDo(sessionHandle);
    }
}
