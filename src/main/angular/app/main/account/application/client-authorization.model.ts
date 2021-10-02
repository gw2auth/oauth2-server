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

export interface ClientAuthorizationLog {
    timestamp: Date;
    messages: string[];
}

export interface ClientAuthorizationLogs {
    page: number;
    nextPage: number;
    logs: ClientAuthorizationLog[];
}