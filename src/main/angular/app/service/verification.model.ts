import {Gw2ApiPermission} from "./general.model";

export interface VerificationChallenge {
    id: number;
    name: string;
    description: string;
    requiredGw2ApiPermissions: Gw2ApiPermission[];
}

export interface VerificationChallengeStart {
    challengeId: number;
    challengeName: string;
    message: string;
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