import {ClientRegistrationPublic} from '../client/client-registration.model';
import {Gw2ApiPermission} from '../../../common/common.model';

export interface Token {
    gw2AccountId: string;
    displayName: string;
    expirationTime: Date;
}

export interface ClientAuthorization {
    clientRegistration: ClientRegistrationPublic;
    accountSub: string;
    authorizedGw2ApiPermissions: Gw2ApiPermission[];
    tokens: Token[];
}

export enum ClientAuthorizationLogType {
    CONSENT = 'CONSENT',
    ACCESS_TOKEN = 'ACCESS_TOKEN'
}

export function clientAuthorizationLogTypeToString(clientAuthorizationLogType: ClientAuthorizationLogType): string {
    switch (clientAuthorizationLogType) {
        case ClientAuthorizationLogType.CONSENT: return 'Consent';
        case ClientAuthorizationLogType.ACCESS_TOKEN: return 'Access-Token request';
    }
}

export interface ClientAuthorizationLog {
    timestamp: Date;
    type: ClientAuthorizationLogType;
    messages: string[];
}

export interface ClientAuthorizationLogs {
    page: number;
    nextPage: number;
    logs: ClientAuthorizationLog[];
}