import {Gw2ApiPermission} from '../../../common/common.model';
import {SafeResourceUrl} from '@angular/platform-browser';

export interface ApiTokenNameMessage {
    apiTokenName: string;
}

export interface TpBuyOrderMessage {
    gw2ItemId: number;
    buyOrderCoins: number;
}

export interface CharacterNameMessage {
    characterName: string;
}

export interface VerificationChallengeResponse {
    id: number;
    requiredGw2ApiPermissions: Gw2ApiPermission[];
}

export interface VerificationChallengeStartResponse {
    challengeId: number;
    message: Map<string, any>;
    nextAllowedStartTime: Date;
}

export interface VerificationChallengePendingResponse {
    challengeId: number;
    gw2AccountId: string;
    startedAt: Date;
}

export interface VerificationChallengeSubmitResponse {
    pending: VerificationChallengePendingResponse | null;
    isSuccess: boolean;
}

export interface VerificationChallengeBootstrapResponse {
    availableChallenges: VerificationChallengeResponse[];
    startedChallenge: VerificationChallengeStartResponse | null;
    pendingChallenges: VerificationChallengePendingResponse[];
}

export interface VerificationChallenge {
    readonly id: number;
    readonly name: string;
    readonly requiredGw2ApiPermissions: Set<Gw2ApiPermission>;
    readonly youtubeEmbedSrcs: ReadonlyArray<SafeResourceUrl>;
    readonly youtubeEmbedSrcsByType: ReadonlyMap<'new' | 'existing', ReadonlyArray<SafeResourceUrl>>;
}

export interface VerificationChallengeStart {
    readonly challenge: VerificationChallenge;
    readonly message: ApiTokenNameMessage | TpBuyOrderMessage | CharacterNameMessage;
    readonly nextAllowedStartTime: Date;
}

export interface VerificationChallengePending {
    readonly challenge: VerificationChallenge;
    readonly name: string;
    readonly gw2AccountId: string;
    readonly startedAt: Date;
    cancellationInProgress: boolean;
}