package com.gw2auth.oauth2.server.adapt;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/*
Not used but don't move / rename since the fully qualified classname is persisted for older entries
 */
public class Gw2AuthAuthenticationManagerResolver {

    @JsonAutoDetect(
            fieldVisibility = JsonAutoDetect.Visibility.NONE,
            setterVisibility = JsonAutoDetect.Visibility.NONE,
            getterVisibility = JsonAutoDetect.Visibility.NONE,
            isGetterVisibility = JsonAutoDetect.Visibility.NONE,
            creatorVisibility = JsonAutoDetect.Visibility.NONE
    )
    public static class Gw2AuthUserAuthentication implements Authentication {

        private final Gw2AuthUserV2 gw2AuthUser;
        private boolean isAuthenticated;

        public Gw2AuthUserAuthentication(@JsonProperty("user") Gw2AuthUserV2 gw2AuthUser) {
            this(gw2AuthUser, true);
        }

        @JsonCreator
        public Gw2AuthUserAuthentication(@JsonProperty("user") Gw2AuthUserV2 gw2AuthUser, @JsonProperty("isAuthenticated") boolean isAuthenticated) {
            this.gw2AuthUser = gw2AuthUser;
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.gw2AuthUser.getAuthorities();
        }

        @Override
        public Object getCredentials() {
            return this.gw2AuthUser;
        }

        @Override
        public Object getDetails() {
            return this.gw2AuthUser;
        }

        @Override
        @JsonGetter("user")
        public Object getPrincipal() {
            return this.gw2AuthUser;
        }

        @Override
        @JsonGetter("isAuthenticated")
        public boolean isAuthenticated() {
            return this.isAuthenticated;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public String getName() {
            return this.gw2AuthUser.getName();
        }
    }
}
