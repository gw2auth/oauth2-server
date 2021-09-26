export enum AuthorizationGrantType {
    AUTHORIZATION_CODE = 'authorization_code',
    REFRESH_TOKEN = 'refresh_token'
}

export function authorizationGrantTypeDisplayName(authorizationGrantType: AuthorizationGrantType): string {
    switch (authorizationGrantType) {
        case AuthorizationGrantType.AUTHORIZATION_CODE: return 'Authorization Code';
        case AuthorizationGrantType.REFRESH_TOKEN: return 'Refresh Token';
    }
}

export interface ClientRegistrationPublic {
    creationTime: Date;
    displayName: string;
    clientId: string;
    redirectUri: string;
}

export interface ClientRegistrationPrivate {
    creationTime: Date;
    displayName: string;
    clientId: string;
    authorizationGrantTypes: AuthorizationGrantType[];
    redirectUri: string;
}

export interface ClientRegistrationCreation {
    clientRegistration: ClientRegistrationPrivate;
    clientSecret: string;
}

export interface ClientRegistrationCreationRequest {
    displayName: string;
    authorizationGrantTypes: AuthorizationGrantType[];
    redirectUri: string;
}