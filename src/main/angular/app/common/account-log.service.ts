import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {AccountLogs} from './account-log.model';

@Injectable({
    providedIn: 'root'
})
export class AccountLogService {

    constructor(private readonly http: HttpClient) {
    }

    getAccountLogs(fields: {[k: string]: any}, page?: number): Observable<AccountLogs> {
        if (fields != undefined) {
            fields['page'] = page;
        }

        return this.http.get<AccountLogs>('/api/account/log', { params: fields })
    }
}