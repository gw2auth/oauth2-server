package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.security.RequestSessionMetadataExtractor;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.nimbusds.jwt.JWTParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

@Service
public class Gw2AuthOAuth2UserService extends AbstractUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> parent;

    public Gw2AuthOAuth2UserService(AccountService accountService, RequestSessionMetadataExtractor requestSessionMetadataExtractor, SessionMetadataService sessionMetadataService, OAuth2UserService<OAuth2UserRequest, OAuth2User> parent) {
        super(accountService, requestSessionMetadataExtractor, sessionMetadataService);
        this.parent = parent;
    }

    @Autowired
    public Gw2AuthOAuth2UserService(AccountService accountService, RequestSessionMetadataExtractor requestSessionMetadataExtractor, SessionMetadataService sessionMetadataService, @Value("${com.gw2auth.login.user-service.use-dummy:false}") boolean useDummyUserService) {
        this(accountService, requestSessionMetadataExtractor, sessionMetadataService, getUserService(useDummyUserService));
    }

    @Override
    public Gw2AuthLoginUser loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return loadUser(userRequest, this.parent.loadUser(userRequest));
    }

    private static OAuth2UserService<OAuth2UserRequest, OAuth2User> getUserService(boolean useDummyUserService) {
        if (useDummyUserService) {
            return new JWTOAuth2UserService();
        }

        return new CustomOAuth2UserService(new DefaultOAuth2UserService(), new JWTOAuth2UserService());
    }

    private static final class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

        private final OAuth2UserService<OAuth2UserRequest, OAuth2User> standard;
        private final OAuth2UserService<OAuth2UserRequest, OAuth2User> internal;

        private CustomOAuth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User> standard, OAuth2UserService<OAuth2UserRequest, OAuth2User> internal) {
            this.standard = standard;
            this.internal = internal;
        }

        @Override
        public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
            final String issuerUri = request.getClientRegistration().getProviderDetails().getIssuerUri();
            if (issuerUri != null && issuerUri.contains("https://gw2auth.com")) {
                return this.internal.loadUser(request);
            }

            return this.standard.loadUser(request);
        }
    }

    private static final class JWTOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

        @Override
        public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
            final String userNameAttribute = request.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            final Map<String, Object> attributes;
            try {
                attributes = JWTParser.parse(request.getAccessToken().getTokenValue()).getJWTClaimsSet().getClaims();
            } catch (ParseException e) {
                throw new IllegalArgumentException(e);
            }

            return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("USER")), attributes, userNameAttribute);
        }
    }
}
