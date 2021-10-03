export interface AccountFederation {
    issuer: string;
    idAtIssuer: string;
}

export interface AccountFederations {
    currentAccountFederation: AccountFederation;
    accountFederations: AccountFederation[];
}
