package com.gw2auth.oauth2.server.configuration.properties;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.*;

@ConfigurationProperties(prefix = "com.gw2auth.client")
public class Gw2AuthClientProperties implements InitializingBean {

    private final Map<String, List<Account>> account = new HashMap<>();

    private final List<Registration> registration = new ArrayList<>();

    public Map<String, List<Account>> getAccount() {
        return account;
    }

    public List<Registration> getRegistration() {
        return registration;
    }

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    private void validate() {
        for (Registration registration : this.registration) {
            if (!this.account.containsKey(registration.getAccount())) {
                throw new IllegalStateException("Referenced account does not exist: " + registration.getAccount());
            } else if (registration.getClientId().isEmpty()) {
                throw new IllegalStateException("client-id must not be empty");
            }
        }
    }

    public static class Registration {

        private String account;
        private String displayName;
        private String clientId;
        private String clientSecret;
        private Set<String> authorizationGrantTypes;
        private String redirectUri;

        public String getAccount() {
            return account;
        }

        public void setAccount(String account) {
            this.account = account;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public Set<String> getAuthorizationGrantTypes() {
            return authorizationGrantTypes;
        }

        public void setAuthorizationGrantTypes(Set<String> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    public static class Account {

        private String issuer;
        private String idAtIssuer;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getIdAtIssuer() {
            return idAtIssuer;
        }

        public void setIdAtIssuer(String idAtIssuer) {
            this.idAtIssuer = idAtIssuer;
        }
    }
}
