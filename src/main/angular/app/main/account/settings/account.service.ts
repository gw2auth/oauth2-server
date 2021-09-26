import {Injectable} from "@angular/core";
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";
import {AccountFederation} from "./account.model";

@Injectable()
export class AccountService {

    constructor(private readonly httpClient: HttpClient) {
    }

    getAccountFederations(): Observable<AccountFederation[]> {
        return this.httpClient.get<AccountFederation[]>('/api/account/federation');
    }

    deleteAccountFederation(issuer: string, idAtIssuer: string): Observable<boolean> {
        return this.httpClient.delete<boolean>('/api/account/federation', { params: { 'issuer': issuer, 'idAtIssuer': idAtIssuer } });
    }

    deleteAccount(): Observable<boolean> {
        return this.httpClient.delete<boolean>('/api/account');
    }
}