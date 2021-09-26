import {Gw2ApiPermission} from './general.model';

export interface Gw2TokenInfo {
    id: string;
    name: string;
    permissions: Gw2ApiPermission[];
}

export interface Gw2Item {
    name: string;
    icon: string;
}