export interface AccountFederationSession {
    id: string;
    creationTime: Date;
    expirationTime: Date;
}

export interface AccountFederation {
    issuer: string;
    idAtIssuer: string;
    sessions: AccountFederationSession[];
}

export interface AccountFederations {
    currentIssuer: string;
    currentIdAtIssuer: string;
    currentSessionId: string;
    federations: AccountFederation[];
}