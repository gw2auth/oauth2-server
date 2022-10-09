import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {
  ClientRegistrationCreation,
  ClientRegistrationCreationRequest,
  ClientRegistrationPrivate,
  ClientRegistrationPrivateSummary
} from './client-registration.model';

@Injectable()
export class ClientRegistrationService {

  constructor(private readonly http: HttpClient) { }

  getClientRegistrations(): Observable<ClientRegistrationPrivate[]> {
    return this.http.get<ClientRegistrationPrivate[]>('/api/client/registration');
  }

  getClientRegistration(clientId: string): Observable<ClientRegistrationPrivate> {
    return this.http.get<ClientRegistrationPrivate>('/api/client/registration/' + encodeURIComponent(clientId));
  }

  getClientRegistrationSummary(clientId: string): Observable<ClientRegistrationPrivateSummary> {
    return this.http.get<ClientRegistrationPrivateSummary>('/api/client/registration/' + encodeURIComponent(clientId) + '/summary');
  }

  createClientRegistration(request: ClientRegistrationCreationRequest): Observable<ClientRegistrationCreation> {
    return this.http.post<ClientRegistrationCreation>('/api/client/registration', request);
  }

  addRedirectUri(clientId: string, redirectUri: string): Observable<ClientRegistrationPrivate> {
    return this.http.put<ClientRegistrationPrivate>('/api/client/registration/' + encodeURIComponent(clientId) + '/redirect-uris', redirectUri);
  }

  removeRedirectUri(clientId: string, redirectUri: string): Observable<ClientRegistrationPrivate> {
    return this.http.delete<ClientRegistrationPrivate>('/api/client/registration/' + encodeURIComponent(clientId) + '/redirect-uris', { params: { redirectUri: redirectUri } });
  }

  regenerateClientSecret(clientId: string): Observable<ClientRegistrationCreation> {
    return this.http.patch<ClientRegistrationCreation>('/api/client/registration/' + encodeURIComponent(clientId) + '/client-secret', null);
  }

  deleteClientRegistration(clientId: string): Observable<void> {
    return this.http.delete<void>('/api/client/registration/' + encodeURIComponent(clientId));
  }
}
