package com.gw2auth.oauth2.server.service.account;

import java.util.List;

public record AccountFederationWithSessions(AccountFederation federation, List<AccountFederationSession> sessions) {
}
