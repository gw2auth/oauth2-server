import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {Params} from '@angular/router';
import {ClientRegistrationPublic} from '../service/client-registration.model';
import {Gw2ApiPermission} from '../service/general.model';
import {Token} from '../service/token.model';


@Injectable()
export class OAuth2ConsentService {

    constructor(private readonly http: HttpClient) {
    }

    getOAuth2ConsentInformation(params: Params): Observable<OAuth2ConsentInformation> {
        return this.http.get<OAuth2ConsentInformation>('/api/oauth2/consent', {params: params});
    }
}

export interface OAuth2ConsentInformation {
    clientRegistration: ClientRegistrationPublic;
    requestedGw2ApiPermissions: Gw2ApiPermission[];
    submitFormUri: string;
    submitFormParameters: Map<string, string[]>;
    cancelUri: string;
    apiTokensWithSufficientPermissions: Token[];
    apiTokensWithInsufficientPermissions: Token[];
}