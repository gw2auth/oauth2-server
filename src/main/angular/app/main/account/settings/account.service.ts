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

    deleteAccountFederation(issuer: string, idAtIssuer: string): Observable<any> {
        return this.httpClient.delete<any>('/api/account/federation', { params: { 'issuer': issuer, 'idAtIssuer': idAtIssuer } });
    }

    deleteAccountSession(id: string): Observable<any> {
        // see: https://stackoverflow.com/questions/53546691/preserving-plus-sign-in-urlencoded-http-post-request
        return this.httpClient.delete<any>('/api/account/session?id=' + encodeURIComponent(id));
    }

    deleteAccount(): Observable<boolean> {
        return this.httpClient.delete<boolean>('/api/account');
    }
}