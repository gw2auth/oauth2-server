import {Inject, Injectable} from '@angular/core';
import {HttpClient, HttpErrorResponse, HttpResponse} from '@angular/common/http';
import {Observable, of} from 'rxjs';
import {catchError} from 'rxjs/operators';
import {DOCUMENT} from '@angular/common';


@Injectable()
export class Oauth2ClientService {

    constructor(private readonly httpClient: HttpClient, @Inject(DOCUMENT) private readonly document: Document) {}

    getToken(code: string, clientId: string, clientSecret: string, redirectUri: string): Observable<HttpResponse<string> | HttpErrorResponse> {
        return this.httpClient.post<HttpResponse<string>>(
            '/api/oauth2/token',
            undefined,
            {
                params: {
                    'grant_type': 'authorization_code',
                    'code': code,
                    'client_id': clientId,
                    'client_secret': clientSecret,
                    'redirect_uri': redirectUri
                },
                observe: 'response',
                responseType: 'text' as 'json'
            }
        ).pipe(catchError((e) => of(e)));
    }
}