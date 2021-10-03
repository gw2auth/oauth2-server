import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {AccountFederations} from './account.model';

@Injectable()
export class AccountService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getAccountFederations(): Observable<AccountFederations> {
        return this.httpClient.get<AccountFederations>('/api/account/federation');
    }

    deleteAccountFederation(issuer: string, idAtIssuer: string): Observable<boolean> {
        return this.httpClient.delete<boolean>('/api/account/federation', { params: { 'issuer': issuer, 'idAtIssuer': idAtIssuer } });
    }

    deleteAccount(): Observable<boolean> {
        return this.httpClient.delete<boolean>('/api/account');
    }
}