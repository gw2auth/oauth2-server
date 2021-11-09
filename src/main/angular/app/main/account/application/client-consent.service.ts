import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {ClientConsent, ClientConsentLogs} from './client-consent.model';

@Injectable()
export class ClientConsentService {

    constructor(private readonly http: HttpClient) {
    }

    getClientConsents(): Observable<ClientConsent[]> {
        return this.http.get<ClientConsent[]>('/api/client/consent');
    }

    getClientConsentLogs(clientId: string, page?: number): Observable<ClientConsentLogs> {
        let params = undefined;
        if (page != undefined) {
            params = {'page': page};
        }

        return this.http.get<ClientConsentLogs>('/api/client/consent/' + encodeURIComponent(clientId) + '/logs', { params: params })
    }

    deleteClientConsent(clientId: string): Observable<void> {
        return this.http.delete<void>('/api/client/consent/' + encodeURIComponent(clientId));
    }
}