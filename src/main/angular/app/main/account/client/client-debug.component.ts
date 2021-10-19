import { Component, OnInit } from '@angular/core';
import {ActivatedRoute} from '@angular/router';
import {ClientRegistrationPrivate} from './client-registration.model';
import {ClientRegistrationService} from './client-registration.service';
import {Gw2ApiPermission} from '../../../common/common.model';
import {faCheck} from '@fortawesome/free-solid-svg-icons';


@Component({
  selector: 'app-client-debug',
  templateUrl: './client-debug.component.html'
})
export class ClientDebugComponent implements OnInit {

  faCheck = faCheck;

  clientRegistration: ClientRegistrationPrivate | null = null;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);
  selectedGw2ApiPermissions = new Set<Gw2ApiPermission>();
  requestVerifiedInformation = true;
  forceConsent = true;

  constructor(private readonly clientRegistrationService: ClientRegistrationService, private readonly activatedRoute: ActivatedRoute) { }

  ngOnInit(): void {
    this.activatedRoute.paramMap.subscribe((params) => {
      const clientId = params.get('clientId');

      this.clientRegistration = null;

      if (clientId != null) {
        this.clientRegistrationService.getClientRegistration(clientId).subscribe((clientRegistration) => this.clientRegistration = clientRegistration);
      }
    });
  }

  onGw2ApiPermissionClick(gw2ApiPermission: Gw2ApiPermission): void {
    if (this.selectedGw2ApiPermissions.has(gw2ApiPermission)) {
      this.selectedGw2ApiPermissions.delete(gw2ApiPermission);
    } else {
      this.selectedGw2ApiPermissions.add(gw2ApiPermission);
    }
  }

  getTestAuthorizeUri(clientRegistration: ClientRegistrationPrivate): string {
    const scopes = [];
    for (let gw2ApiPermission of this.selectedGw2ApiPermissions) {
      scopes.push('gw2:' + gw2ApiPermission);
    }

    if (this.requestVerifiedInformation) {
      scopes.push('gw2auth:verified');
    }

    const query = new URLSearchParams();
    query.set('response_type', 'code');
    query.set('client_id', clientRegistration.clientId);
    query.set('scope', scopes.join(' '));
    query.set('redirect_uri', clientRegistration.redirectUri);
    query.set('state', clientRegistration.clientId);

    if (this.forceConsent) {
      query.set('consent', 'force');
    }

    return '/oauth2/authorize?' + query.toString();
  }
}
