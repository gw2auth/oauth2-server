export interface AccountFederation {
    issuer: string;
    idAtIssuer: string;
}

export interface AccountFederations {
    currentAccountFederation: AccountFederation;
    accountFederations: AccountFederation[];
}

export interface AccountSession {
    id: string;
    creationTime: Date;
    expirationTime: Date;
}

export interface AccountSessions {
    currentAccountSessionId: string;
    accountSessions: AccountSession[];
}
