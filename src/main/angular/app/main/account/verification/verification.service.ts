import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {VerificationChallenge, VerificationChallengeBootstrap, VerificationChallengePending, VerificationChallengeStart, VerificationChallengeSubmit} from './verification.model';

@Injectable()
export class VerificationService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getBootstrap(): Observable<VerificationChallengeBootstrap> {
        return this.httpClient.get<VerificationChallengeBootstrap>('/api/verification/bootstrap');
    }

    getAvailableChallenges(): Observable<VerificationChallenge[]> {
        return this.httpClient.get<VerificationChallenge[]>('/api/verification/challenge');
    }

    getStartedChallenge(): Observable<VerificationChallengeStart> {
        return this.httpClient.get<VerificationChallengeStart>('/api/verification');
    }

    getPendingChallenges(): Observable<VerificationChallengePending[]> {
        return this.httpClient.get<VerificationChallengePending[]>('/api/verification/pending');
    }

    startChallenge(challengeId: number): Observable<VerificationChallengeStart> {
        return this.httpClient.post<VerificationChallengeStart>('/api/verification', undefined, { params: { 'challengeId': challengeId } });
    }

    submitChallenge(token: string): Observable<VerificationChallengeSubmit> {
        return this.httpClient.post<VerificationChallengeSubmit>('/api/verification/pending', undefined, { params: { 'token': token } });
    }
}