import {Gw2ApiPermission} from './common.model';

export interface Gw2Account {
    name: string;
}

export interface Gw2TokenInfo {
    id: string;
    name: string;
    permissions: Gw2ApiPermission[];
}

export interface Gw2Item {
    name: string;
    icon: string;
}