import {ClientRegistrationPublic} from '../client/client-registration.model';
import {Gw2ApiPermission} from '../../../common/common.model';

export interface ClientConsent {
    clientRegistration: ClientRegistrationPublic;
    accountSub: string;
    authorizedGw2ApiPermissions: Gw2ApiPermission[];
    authorizedVerifiedInformation: boolean;
}

export enum ClientConsentLogType {
    CONSENT = 'CONSENT',
    AUTHORIZATION = 'AUTHORIZATION',
    ACCESS_TOKEN = 'ACCESS_TOKEN'
}

export function clientConsentLogTypeToString(clientAuthorizationLogType: ClientConsentLogType): string {
    switch (clientAuthorizationLogType) {
        case ClientConsentLogType.CONSENT: return 'Consent';
        case ClientConsentLogType.AUTHORIZATION: return 'Authorization';
        case ClientConsentLogType.ACCESS_TOKEN: return 'Access-Token request';
    }
}

export interface ClientConsentLog {
    timestamp: Date;
    type: ClientConsentLogType;
    messages: string[];
}

export interface ClientConsentLogs {
    page: number;
    nextPage: number;
    logs: ClientConsentLog[];
}