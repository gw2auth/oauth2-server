import {ClientRegistrationPublic} from '../client/client-registration.model';
import {Gw2ApiPermission} from '../../../common/common.model';
import {AccountLog} from '../../../common/account-log.model';

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

export function tryGetLogType(log: AccountLog): string {
    if (log.fields['type']) {
        switch (log.fields['type']) {
            case ClientConsentLogType.CONSENT: return 'Consent';
            case ClientConsentLogType.AUTHORIZATION: return 'Authorization';
            case ClientConsentLogType.ACCESS_TOKEN: return 'Access-Token request';
        }
    }

    return 'Unknown';
}