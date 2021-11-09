import {Gw2ApiPermission} from '../../../common/common.model';

export interface Token {
    gw2AccountId: string;
    displayName: string;
}

export interface ClientAuthorization {
    id: string;
    creationTime: Date;
    lastUpdateTime: Date;
    displayName: string;
    authorizedGw2ApiPermissions: Gw2ApiPermission[];
    authorizedVerifiedInformation: boolean;
    tokens: Token[];
}
