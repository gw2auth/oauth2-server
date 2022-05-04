import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Observable} from 'rxjs';
import {Params} from '@angular/router';
import {ClientRegistrationPublic} from '../main/account/client/client-registration.model';
import {Gw2ApiPermission} from '../common/common.model';


@Injectable()
export class OAuth2ConsentService {

    constructor(private readonly http: HttpClient) {
    }

    getOAuth2ConsentInformation(params: Params): Observable<OAuth2ConsentInformation> {
        return this.http.get<OAuth2ConsentInformation>('/api/oauth2/consent', {params: params});
    }
}

export interface MinimalToken {
    gw2AccountId: string;
    gw2ApiToken: string;
    displayName: string;
    isValid: boolean;
    isVerified: boolean;
}

export interface OAuth2ConsentInformation {
    clientRegistration: ClientRegistrationPublic;
    requestedGw2ApiPermissions: Gw2ApiPermission[];
    requestedVerifiedInformation: boolean;
    submitFormUri: string;
    submitFormParameters: Map<string, string[]>;
    cancelUri: string;
    apiTokensWithSufficientPermissions: MinimalToken[];
    apiTokensWithInsufficientPermissions: MinimalToken[];
    previouslyConsentedGw2AccountIds: string[];
}