import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {
    VerificationChallengeResponse,
    VerificationChallengeBootstrapResponse,
    VerificationChallengePendingResponse,
    VerificationChallengeStartResponse,
    VerificationChallengeSubmitResponse,
    VerificationChallenge,
    VerificationChallengeStart,
    ApiTokenNameMessage,
    TpBuyOrderMessage,
    CharacterNameMessage,
    VerificationChallengePending
} from './verification.model';
import {DomSanitizer, SafeResourceUrl} from '@angular/platform-browser';
import {Gw2ApiPermission} from '../../../common/common.model';
import {Token} from '../../../common/token.model';


@Injectable()
export class VerificationService {

    constructor(private readonly httpClient: HttpClient, private readonly sanitizer: DomSanitizer) {
    }

    getBootstrap(): Observable<VerificationChallengeBootstrapResponse> {
        return this.httpClient.get<VerificationChallengeBootstrapResponse>('/api/verification/bootstrap');
    }

    getAvailableChallenges(): Observable<VerificationChallengeResponse[]> {
        return this.httpClient.get<VerificationChallengeResponse[]>('/api/verification/challenge');
    }

    getStartedChallenge(): Observable<VerificationChallengeStartResponse> {
        return this.httpClient.get<VerificationChallengeStartResponse>('/api/verification');
    }

    getPendingChallenges(): Observable<VerificationChallengePendingResponse[]> {
        return this.httpClient.get<VerificationChallengePendingResponse[]>('/api/verification/pending');
    }

    startChallenge(challengeId: number): Observable<VerificationChallengeStartResponse> {
        return this.httpClient.post<VerificationChallengeStartResponse>('/api/verification', undefined, { params: { 'challengeId': challengeId } });
    }

    submitChallenge(token: string): Observable<VerificationChallengeSubmitResponse> {
        return this.httpClient.post<VerificationChallengeSubmitResponse>('/api/verification/pending', undefined, { params: { 'token': token } });
    }

    cancelPendingChallenge(gw2AccountId: string): Observable<void> {
        return this.httpClient.delete<void>('/api/verification/pending/' + encodeURIComponent(gw2AccountId));
    }

    challengeFromResponse(v: VerificationChallengeResponse): VerificationChallenge {
        let name: string;
        const youtubeEmbedSrcs: SafeResourceUrl[] = [];
        const youtubeEmbedSrcsByType = new Map<'new' | 'existing', SafeResourceUrl[]>();

        switch (v.id) {
            case 1: {
                name = 'API Token name';
                this.addYoutubeEmbedSrc('https://www.youtube.com/embed/xgaG9ysH3is', null, youtubeEmbedSrcs, youtubeEmbedSrcsByType);
                break;
            }
            case 2: {
                name = 'TP Buy-Order';
                this.addYoutubeEmbedSrc('https://www.youtube.com/embed/Lt50s84D2b4', 'new', youtubeEmbedSrcs, youtubeEmbedSrcsByType);
                this.addYoutubeEmbedSrc('https://www.youtube.com/embed/W1Gu4kCLx0g', 'existing', youtubeEmbedSrcs, youtubeEmbedSrcsByType);
                break;
            }
            case 3: {
                name = 'Character name';
                this.addYoutubeEmbedSrc('https://www.youtube.com/embed/SD7FqZC9zwA', 'new', youtubeEmbedSrcs, youtubeEmbedSrcsByType);
                this.addYoutubeEmbedSrc('https://www.youtube.com/embed/MJMdTtlId1Y', 'existing', youtubeEmbedSrcs, youtubeEmbedSrcsByType);
                break;
            }
            default: throw new Error();
        }

        return {
            id: v.id,
            name: name,
            requiredGw2ApiPermissions: new Set<Gw2ApiPermission>(v.requiredGw2ApiPermissions),
            youtubeEmbedSrcs: youtubeEmbedSrcs,
            youtubeEmbedSrcsByType: youtubeEmbedSrcsByType,
        }
    }

    challengeStartFromResponse(v: VerificationChallengeStartResponse, challenges: VerificationChallenge[]): VerificationChallengeStart {
        const challenge = challenges.find((challenge) => challenge.id == v.challengeId);
        if (challenge == undefined) {
            throw Error();
        }

        let message: ApiTokenNameMessage | TpBuyOrderMessage | CharacterNameMessage;

        switch (v.challengeId) {
            case 1: {
                message = <ApiTokenNameMessage><unknown>v.message;
                break;
            }
            case 2: {
                message = <TpBuyOrderMessage><unknown>v.message;
                break;
            }
            case 3: {
                message = <CharacterNameMessage><unknown>v.message;
                break;
            }
            default: throw Error();
        }

        return {
            challenge: challenge,
            message: message,
            nextAllowedStartTime: v.nextAllowedStartTime,
        }
    }

    challengePendingFromResponse(v: VerificationChallengePendingResponse, tokens: Token[], challenges: VerificationChallenge[]): VerificationChallengePending {
        const challenge = challenges.find((challenge) => challenge.id == v.challengeId);
        if (challenge == undefined) {
            throw Error();
        }

        const token = tokens.find((token) => token.gw2AccountId == v.gw2AccountId);
        let name = v.gw2AccountId;

        if (token != undefined) {
            name = token.displayName;
        }

        return {
            challenge: challenge,
            name: name,
            gw2AccountId: v.gw2AccountId,
            startedAt: v.startedAt,
            cancellationInProgress: false,
        }
    }

    private addYoutubeEmbedSrc(url: string,
                               type: 'new' | 'existing' | null,
                               youtubeEmbedSrcs: SafeResourceUrl[],
                               youtubeEmbedSrcsByType: Map<'new' | 'existing', SafeResourceUrl[]>) {

        const safeUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
        youtubeEmbedSrcs.push(safeUrl);

        if (type == null) {
            VerificationService.pushSafe('new', safeUrl, youtubeEmbedSrcsByType);
            VerificationService.pushSafe('existing', safeUrl, youtubeEmbedSrcsByType);
        } else {
            VerificationService.pushSafe(type, safeUrl, youtubeEmbedSrcsByType);
        }
    }

    private static pushSafe<K, V>(k: K, v: V, map: Map<K, V[]>): void {
        if (!map.has(k)) {
            map.set(k, []);
        }

        map.get(k)!.push(v);
    }
}