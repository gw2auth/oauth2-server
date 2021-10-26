import {Injectable} from '@angular/core';
import {HttpClient, HttpErrorResponse} from '@angular/common/http';
import {Observable, of} from 'rxjs';
import {VerificationChallenge, VerificationChallengeBootstrap, VerificationChallengePending, VerificationChallengeStart, VerificationChallengeSubmit} from './verification.model';
import {catchError} from 'rxjs/operators';
import {ApiError} from '../../../common/common.model';

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

    startChallenge(challengeId: number): Observable<VerificationChallengeStart | ApiError> {
        return this.httpClient.post<VerificationChallengeStart>('/api/verification', undefined, { params: { 'challengeId': challengeId } })
            .pipe(catchError((e: HttpErrorResponse) => {
                return of(e.error);
            }));
    }

    submitChallenge(token: string): Observable<VerificationChallengeSubmit | ApiError> {
        return this.httpClient.post<VerificationChallengeSubmit>('/api/verification/pending', undefined, { params: { 'token': token } })
            .pipe(catchError((e: HttpErrorResponse) => {
                return of(e.error);
            }));
    }
}