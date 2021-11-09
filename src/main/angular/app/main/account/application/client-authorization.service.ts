import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {ClientAuthorization} from './client-authorization.model';

@Injectable()
export class ClientAuthorizationService {

    constructor(private readonly http: HttpClient) {
    }

    getClientAuthorizations(clientId: string): Observable<ClientAuthorization[]> {
        return this.http.get<ClientAuthorization[]>('/api/client/authorization/' + encodeURIComponent(clientId));
    }

    deleteClientAuthorization(id: string): Observable<void> {
        return this.http.delete<void>('/api/client/authorization/_/' + encodeURIComponent(id));
    }
}