import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {ClientRegistrationCreation, ClientRegistrationCreationRequest, ClientRegistrationPrivate} from './client-registration.model';

@Injectable({
  providedIn: 'root'
})
export class ClientRegistrationService {

  constructor(private readonly http: HttpClient) { }

  getClientRegistrations(): Observable<ClientRegistrationPrivate[]> {
    return this.http.get<ClientRegistrationPrivate[]>('/api/client/registration');
  }

  getClientRegistration(clientId: string): Observable<ClientRegistrationPrivate> {
    return this.http.get<ClientRegistrationPrivate>('/api/client/registration/' + encodeURIComponent(clientId));
  }

  createClientRegistration(request: ClientRegistrationCreationRequest): Observable<ClientRegistrationCreation> {
    return this.http.post<ClientRegistrationCreation>('/api/client/registration', request);
  }

  deleteClientRegistration(clientId: string): Observable<void> {
    return this.http.delete<void>('/api/client/registration/' + encodeURIComponent(clientId));
  }
}
