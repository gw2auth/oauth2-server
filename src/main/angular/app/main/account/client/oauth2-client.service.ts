import {Inject, Injectable} from '@angular/core';
import {HttpClient, HttpErrorResponse, HttpResponse} from '@angular/common/http';
import {Observable, of} from 'rxjs';
import {catchError} from 'rxjs/operators';
import {DOCUMENT} from '@angular/common';


export type GrantType = 'authorization_code' | 'refresh_token';

@Injectable()
export class Oauth2ClientService {

    constructor(private readonly httpClient: HttpClient, @Inject(DOCUMENT) private readonly document: Document) {}

    getToken(grantType: GrantType, codeOrRefreshToken: string, clientId: string, clientSecret: string, redirectUri: string | null): Observable<HttpResponse<string> | HttpErrorResponse> {
        const params: {[_: string]: string} = {
            'grant_type': grantType,
            'client_id': clientId,
            'client_secret': clientSecret
        };

        switch (grantType) {
            case 'authorization_code': {
                params['code'] = codeOrRefreshToken;
                params['redirect_uri'] = redirectUri!;
                break;
            }
            case 'refresh_token': {
                params['refresh_token'] = codeOrRefreshToken;
                break;
            }
        }

        return this.httpClient.post<string>(
            '/api/oauth2/token',
            undefined,
            {params: params, observe: 'response', responseType: 'text' as 'json'}
        ).pipe(catchError((e) => of(e as HttpErrorResponse)));
    }
}