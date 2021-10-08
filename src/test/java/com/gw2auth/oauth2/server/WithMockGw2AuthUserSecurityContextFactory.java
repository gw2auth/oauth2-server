package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.service.account.AccountFederation;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.List;
import java.util.Map;

public class WithMockGw2AuthUserSecurityContextFactory implements WithSecurityContextFactory<WithMockGw2AuthUser> {

    @Override
    public SecurityContext createSecurityContext(WithMockGw2AuthUser annotation) {
        final SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(createAuthentication(annotation.accountId(), annotation.issuer(), annotation.idAtIssuer()));

        return context;
    }

    public static Gw2AuthUser withMockGw2AuthUser(long accountId, String issuer, String idAtIssuer) {
        final Authentication authentication = createAuthentication(accountId, issuer, idAtIssuer);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return (Gw2AuthUser) authentication.getPrincipal();
    }

    private static Authentication createAuthentication(long accountId, String issuer, String idAtIssuer) {
        final Gw2AuthUser user = new Gw2AuthUser(
                new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("USER")), Map.of("sub", idAtIssuer), "sub"),
                accountId,
                new AccountFederation(issuer, idAtIssuer)
        );

        return new UsernamePasswordAuthenticationToken(user, "N/A", user.getAuthorities());
    }
}
