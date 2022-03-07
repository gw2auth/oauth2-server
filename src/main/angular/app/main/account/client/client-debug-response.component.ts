import {Component, Inject, OnInit} from '@angular/core';
import {ActivatedRoute} from '@angular/router';
import {ClientRegistrationPrivate} from './client-registration.model';
import {ClientRegistrationService} from './client-registration.service';
import {faCheck} from '@fortawesome/free-solid-svg-icons';
import {Oauth2ClientService, GrantType} from './oauth2-client.service';
import {HttpErrorResponse, HttpResponse} from '@angular/common/http';
import {DOCUMENT} from "@angular/common";


@Component({
  selector: 'app-client-debug-response',
  templateUrl: './client-debug-response.component.html'
})
export class ClientDebugResponseComponent implements OnInit {

  faCheck = faCheck;

  clientRegistration: ClientRegistrationPrivate | null = null;
  error: string | null = null;
  errorDescription: string | null = null;
  codeOrRefreshToken: string | null = null;
  grantType: GrantType = 'authorization_code';

  clientSecret = '';
  codeRequestInProgress = false;
  hasResponse = false;
  codeRequestResponseText: string | null = null;
  codeRequestResponseAccessToken: string | null = null;
  codeRequestResponseRefreshToken: string | null = null;
  codeRequestResponseTokenType: string | null = null;
  codeRequestResponseScope: string | null = null;
  codeRequestResponseExpiresIn: number | null = null;

  constructor(private readonly clientRegistrationService: ClientRegistrationService, private readonly oauth2ClientService: Oauth2ClientService, private readonly activatedRoute: ActivatedRoute, @Inject(DOCUMENT) private readonly document: Document) { }

  ngOnInit(): void {
    this.activatedRoute.queryParamMap.subscribe((query) => {
      this.codeOrRefreshToken = query.get('code');
      this.grantType = 'authorization_code';

      this.error = query.get('error');
      this.errorDescription = query.get('error_description');

      const clientId = query.get('state');
      this.clientRegistration = null;

      if (clientId != null) {
        this.clientRegistrationService.getClientRegistration(clientId).subscribe((clientRegistration) => this.clientRegistration = clientRegistration);
      }
    });
  }

  onRequestTokensClick(): void {
    this.codeRequestInProgress = true;

    let correctRedirectUri = '';
    for (let redirectUri of this.clientRegistration!.redirectUris) {
      if (redirectUri.startsWith(this.document.location.origin) && redirectUri.endsWith('/account/client/debug')) {
        correctRedirectUri = redirectUri;
        break;
      }
    }

    this.oauth2ClientService.getToken(this.grantType!, this.codeOrRefreshToken!, this.clientRegistration!.clientId, this.clientSecret, correctRedirectUri).subscribe((response) => {
      this.codeRequestResponseText = null;
      this.codeRequestResponseAccessToken = null;
      this.codeRequestResponseRefreshToken = null;
      this.codeRequestResponseTokenType = null;
      this.codeRequestResponseScope = null;
      this.codeRequestResponseExpiresIn = null;


      if (response.status == 200) {
        const json = JSON.parse((<HttpResponse<string>> response).body!);

        if (json.access_token != undefined) {
          this.codeRequestResponseAccessToken = ClientDebugResponseComponent.jwtToString(ClientDebugResponseComponent.parseJWT(json.access_token));
        }

        if (json.refresh_token != undefined) {
          this.codeRequestResponseRefreshToken = json.refresh_token;

          this.codeOrRefreshToken = this.codeRequestResponseRefreshToken;
          this.grantType = 'refresh_token';
        }

        if (json.token_type != undefined) {
          this.codeRequestResponseTokenType = json.token_type;
        }

        if (json.scope != undefined) {
          this.codeRequestResponseScope = json.scope;
        }

        if (json.expires_in != undefined) {
          this.codeRequestResponseExpiresIn = json.expires_in;
        }
      } else if ((<HttpErrorResponse> response).name == 'HttpErrorResponse' && (<HttpErrorResponse> response).error == null) {
        this.codeRequestResponseText = 'Unknown error: ' + response.status;
      } else {
        this.codeRequestResponseText = JSON.stringify(response, null, '\t');
      }

      this.hasResponse = this.codeRequestResponseText != null
          || this.codeRequestResponseAccessToken != null
          || this.codeRequestResponseRefreshToken != null
          || this.codeRequestResponseTokenType != null
          || this.codeRequestResponseScope != null
          || this.codeRequestResponseExpiresIn != null;

      this.codeRequestInProgress = false;
    });
  }

  private static parseJWT(text: string): [any, any, string] {
    const parts = text.split('.');

    if (parts.length != 3) {
      return [{}, {}, ''];
    }

    return [
      JSON.parse(ClientDebugResponseComponent.base64URLDecode(parts[0])),
      JSON.parse(ClientDebugResponseComponent.base64URLDecode(parts[1])),
      parts[2]
    ];
  }

  private static base64URLDecode(arg: string): string {
    let s = arg;
    s = s.replace('-', '+');
    s = s.replace('_', '/');

    switch (s.length % 4) {
      case 0: break;
      case 2: s += '=='; break;
      case 3: s += '='; break;
    }

    return atob(arg);
  }

  private static jwtToString(jwt: [any, any, string]): string {
    let text = '';
    text += JSON.stringify(jwt[0], null, '\t') + '\n\n';
    text += JSON.stringify(jwt[1], null, '\t') + '\n\n';
    text += jwt[2];

    return text;
  }
}
