import { Component, OnInit } from '@angular/core';
import {ClientRegistrationService} from './client-registration.service';
import {AuthorizationGrantType, authorizationGrantTypeDisplayName, ClientRegistrationCreation,} from './client-registration.model';
import {catchError} from 'rxjs/operators';
import {ToastService} from '../../../toast/toast.service';
import {ApiError} from '../../../common/common.model';
import {of} from 'rxjs';

@Component({
  selector: 'app-client-create',
  templateUrl: './client-create.component.html'
})
export class ClientCreateComponent implements OnInit {

  displayName = '';
  authorizationGrantTypes = Object.values(AuthorizationGrantType);
  redirectUri = '';

  createInProgress = false;
  showCreateButton = true;

  creationTime: Date | null = null;
  clientId: string | null = null;
  clientSecret: string | null = null;

  constructor(private readonly clientRegistrationService: ClientRegistrationService, private readonly toastService: ToastService) { }

  ngOnInit(): void {
  }

  authorizationGrantTypeDisplayName(authorizationGrantType: AuthorizationGrantType): string {
      return authorizationGrantTypeDisplayName(authorizationGrantType);
  }

  onCreateClientClick(): void {
    this.createInProgress = true;

    this.clientRegistrationService.createClientRegistration({displayName: this.displayName, authorizationGrantTypes: this.authorizationGrantTypes, redirectUri: this.redirectUri})
        .pipe(catchError((e) => {
          const error = e.error as ApiError;

          this.toastService.show('Failed to create client', 'The Client could not be created: ' + error.message);
          this.createInProgress = false;

          return of<ClientRegistrationCreation>();
        }))
        .subscribe((response: ClientRegistrationCreation) => {
          this.showCreateButton = false;

          this.displayName = response.clientRegistration.displayName;
          this.authorizationGrantTypes = response.clientRegistration.authorizationGrantTypes;
          this.redirectUri = response.clientRegistration.redirectUri;
          this.creationTime = response.clientRegistration.creationTime;
          this.clientId = response.clientRegistration.clientId;
          this.clientSecret = response.clientSecret;
        });
  }
}
