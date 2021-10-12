package com.gw2auth.oauth2.server.util;

import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpSession;
import java.util.Optional;

public class AuthenticationHelper {

    public static Optional<Gw2AuthUser> getUser() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(Authentication::getPrincipal)
                .filter(Gw2AuthUser.class::isInstance)
                .map(Gw2AuthUser.class::cast);

    }

    public static Optional<Gw2AuthUser> getUser(HttpSession session) {
        return Optional.ofNullable(session)
                .flatMap((s) -> Optional.ofNullable(s.getAttribute("SPRING_SECURITY_CONTEXT")))
                .filter(SecurityContext.class::isInstance)
                .map(SecurityContext.class::cast)
                .map(SecurityContext::getAuthentication)
                .map(Authentication::getPrincipal)
                .filter(Gw2AuthUser.class::isInstance)
                .map(Gw2AuthUser.class::cast);
    }
}
