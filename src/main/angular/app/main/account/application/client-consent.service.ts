import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {ClientConsent, tryGetLogType} from './client-consent.model';
import {AccountLogs} from '../../../common/account-log.model';
import {AccountLogService} from '../../../common/account-log.service';
import {map} from 'rxjs/operators';

@Injectable()
export class ClientConsentService {

    constructor(private readonly http: HttpClient, private readonly accountLogService: AccountLogService) {
    }

    getClientConsents(): Observable<ClientConsent[]> {
        return this.http.get<ClientConsent[]>('/api/client/consent');
    }

    getClientConsentLogs(clientId: string, page?: number): Observable<AccountLogs> {
        return this.accountLogService.getAccountLogs({'client_id': clientId}, page)
            .pipe(map((value) => {
                value.logs = value.logs.filter((log) => tryGetLogType(log) != 'Unknown');
                return value;
            }));
    }

    deleteClientConsent(clientId: string): Observable<void> {
        return this.http.delete<void>('/api/client/consent/' + encodeURIComponent(clientId));
    }
}