import { Injectable } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {Token} from './token.model';

@Injectable({
  providedIn: 'root'
})
export class TokenService {

  constructor(private readonly http: HttpClient) { }

  getTokens(): Observable<Token[]> {
    return this.http.get<Token[]>('/api/token');
  }

  createToken(gw2ApiToken: string): Observable<Token> {
    return this.http.post<Token>('/api/token', gw2ApiToken);
  }

  updateToken(gw2AccountId: string, displayName?: string, gw2ApiToken?: string): Observable<Token> {
    const body = new FormData();

    if (displayName != undefined) {
      body.set('displayName', displayName);
    }

    if (gw2ApiToken != undefined) {
      body.set('gw2ApiToken', gw2ApiToken);
    }

    return this.http.patch<Token>('/api/token/' + encodeURIComponent(gw2AccountId), body);
  }

  deleteToken(gw2AccountId: string): Observable<any> {
    return this.http.delete<any>('/api/token/' + encodeURIComponent(gw2AccountId));
  }
}
