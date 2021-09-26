import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {ClientAuthorization, ClientAuthorizationLogs} from './client-authorization.model';

@Injectable()
export class ClientAuthorizationService {

    constructor(private readonly http: HttpClient) {
    }

    getClientAuthorizations(): Observable<ClientAuthorization[]> {
        return this.http.get<ClientAuthorization[]>('/api/client/authorization');
    }

    getClientAuthorizationLogs(clientId: string, page?: number): Observable<ClientAuthorizationLogs> {
        let params = undefined;
        if (page != undefined) {
            params = {'page': page};
        }

        return this.http.get<ClientAuthorizationLogs>('/api/client/authorization/' + encodeURIComponent(clientId) + '/logs', { params: params })
    }

    deleteClientAuthorization(clientId: string): Observable<void> {
        return this.http.delete<void>('/api/client/authorization/' + encodeURIComponent(clientId));
    }
}