import {Gw2ApiPermission} from '../../../service/general.model';

export interface ApiTokenNameMessage {
    apiTokenName: string;
}

export interface TpBuyOrderMessage {
    gw2ItemId: number;
    buyOrderCoins: number;
}

export interface VerificationChallenge {
    id: number;
    requiredGw2ApiPermissions: Gw2ApiPermission[];
}

export interface VerificationChallengeStart {
    challengeId: number;
    message: Map<string, any>;
}

export interface VerificationChallengePending {
    challengeId: number;
    gw2AccountId: string;
    startedAt: Date;
}

export interface VerificationChallengeSubmit {
    pending: VerificationChallengePending | null;
    isSuccess: boolean;
}

export interface VerificationChallengeBootstrap {
    availableChallenges: VerificationChallenge[];
    startedChallenge: VerificationChallengeStart | null;
    pendingChallenges: VerificationChallengePending[];
}