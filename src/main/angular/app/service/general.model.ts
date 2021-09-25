export enum Gw2ApiPermission {
    ACCOUNT = 'account',
    BUILDS = 'builds',
    CHARACTERS = 'characters',
    GUILDS = 'guilds',
    INVENTORIES = 'inventories',
    PROGRESSION = 'progression',
    PVP = 'pvp',
    TRADINGPOST = 'tradingpost',
    UNLOCKS = 'unlocks',
    WALLET = 'wallet'
}

export interface ApiError {
    type: string;
    message: string;
}

export function gw2ApiPermissionDisplayName(gw2ApiPermission: Gw2ApiPermission): string {
    switch (gw2ApiPermission) {
        case Gw2ApiPermission.ACCOUNT: return 'Account';
        case Gw2ApiPermission.BUILDS: return 'Builds';
        case Gw2ApiPermission.CHARACTERS: return 'Characters';
        case Gw2ApiPermission.GUILDS: return 'Guilds';
        case Gw2ApiPermission.INVENTORIES: return 'Inventories';
        case Gw2ApiPermission.PROGRESSION: return 'Progression';
        case Gw2ApiPermission.PVP: return 'PvP';
        case Gw2ApiPermission.TRADINGPOST: return 'Tradingpost';
        case Gw2ApiPermission.UNLOCKS: return 'Unlocks';
        case Gw2ApiPermission.WALLET: return 'Wallet';
    }
}