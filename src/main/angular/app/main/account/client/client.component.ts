import {Component, Inject, OnInit} from '@angular/core';
import {ClientRegistrationService} from './client-registration.service';
import {AuthorizationGrantType, ClientRegistrationPrivate, authorizationGrantTypeDisplayName} from './client-registration.model';
import {faAngleDoubleDown, faAngleDoubleUp, faTrashAlt, faCopy, faRedo, faPlusSquare} from '@fortawesome/free-solid-svg-icons';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {ToastService} from '../../../toast/toast.service';
import {ApiError} from '../../../common/common.model';
import {DOCUMENT} from '@angular/common';
import {firstValueFrom} from 'rxjs';
import {RegenerateClientSecretModalComponent} from './regenerate-client-secret-modal.component';


@Component({
  selector: 'app-client',
  templateUrl: './client.component.html'
})
export class ClientComponent implements OnInit {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;
  faTrashAlt = faTrashAlt;
  faCopy = faCopy;
  faRedo = faRedo;
  faPlusSquare = faPlusSquare;

  clientRegistrations: ClientRegistrationPrivate[] = [];
  clientSecretsByClientId = new Map<string, string>();

  constructor(private readonly clientRegistrationService: ClientRegistrationService, private readonly modalService: NgbModal, private readonly toastService: ToastService, @Inject(DOCUMENT) private readonly document: Document) { }

  ngOnInit(): void {
    this.clientRegistrationService.getClientRegistrations().subscribe((clientRegistrations) => this.clientRegistrations = clientRegistrations);
  }

  authorizationGrantTypeDisplayName(authorizationGrantType: AuthorizationGrantType): string {
    return authorizationGrantTypeDisplayName(authorizationGrantType);
  }

  hasTestRedirectUri(clientRegistration: ClientRegistrationPrivate): boolean {
      for (let redirectUri of clientRegistration.redirectUris) {
          if (redirectUri.startsWith(this.document.location.origin) && redirectUri.endsWith('/account/client/debug')) {
              return true;
          }
      }

      return false;
  }

  getClientSecretSafe(clientRegistration: ClientRegistrationPrivate): string {
      const clientSecret = this.clientSecretsByClientId.get(clientRegistration.clientId);
      if (clientSecret != undefined) {
          return clientSecret;
      } else {
          return '';
      }
  }

  onCopyClick(tooltip: any, value: string): void {
      navigator.clipboard.writeText(value)
          .then(() => tooltip.open({message: 'Copied!'}))
          .catch(() => tooltip.open({message: 'Copy failed'}));
  }

  onAddRedirectUriClick(clientRegistration: ClientRegistrationPrivate, redirectUriElement: HTMLInputElement): void {
      firstValueFrom(this.clientRegistrationService.addRedirectUri(clientRegistration.clientId, redirectUriElement.value))
          .then((clientRegistration) => {
              this.toastService.show('Redirect-URI added', 'The Redirect-URI has been added successfully');

              for (let i = 0; i < this.clientRegistrations.length; i++) {
                  if (this.clientRegistrations[i].clientId == clientRegistration.clientId) {
                      this.clientRegistrations[i] = clientRegistration;
                      break;
                  }
              }

              redirectUriElement.value = '';
          })
          .catch((apiError: ApiError) => {
              this.toastService.show('Redirect-URI addition failed', 'The Redirect-URI addition failed: ' + apiError.message);
          });
  }

  trackByClientRegistration(idx: number, clientRegistration: ClientRegistrationPrivate): string {
      return clientRegistration.clientId;
  }

  openRegenerateClientSecretModal(clientRegistration: ClientRegistrationPrivate): void {
      const modalRef = this.modalService.open(RegenerateClientSecretModalComponent);
      modalRef.componentInstance.clientRegistration = clientRegistration;

      modalRef.result
          .then((confirmed: boolean) => {
              if (confirmed) {
                  firstValueFrom(this.clientRegistrationService.regenerateClientSecret(clientRegistration.clientId))
                      .then((clientRegistrationCreation) => {
                          this.toastService.show('Client-Secret generated', 'The Client-Secret has been generated successfully');
                          this.clientSecretsByClientId.set(clientRegistrationCreation.clientRegistration.clientId, clientRegistrationCreation.clientSecret);
                      })
                      .catch((apiError: ApiError) => {
                          this.toastService.show('Client-Secret generation failed', apiError.message);
                      });
              }
          })
          .catch(() => {});
  }

  openDeleteRedirectUriModal(clientRegistration: ClientRegistrationPrivate, redirectUri: string): void {
      const modalRef = this.modalService.open(DeleteModalComponent);
      modalRef.componentInstance.entityType = 'Redirect-URI';
      modalRef.componentInstance.entityName = redirectUri;

      const clientId = clientRegistration.clientId;

      modalRef.result
          .then((confirmed: boolean) => {
              if (confirmed) {
                  firstValueFrom(this.clientRegistrationService.removeRedirectUri(clientId, redirectUri))
                      .then((clientRegistration) => {
                          this.toastService.show('Redirect-URI deleted', 'The Redirect-URI has been deleted successfully');

                          this.clientRegistrations = this.clientRegistrations.map((v, index, arr) => {
                              if (v.clientId == clientId) {
                                  v = clientRegistration;
                              }

                              return v;
                          });
                      })
                      .catch((apiError: ApiError) => {
                          this.toastService.show('Redirect-URI deletion failed', 'The Redirect-URI deletion failed: ' + apiError.message);
                      })
              }
          })
          .catch(() => {});
  }

  openDeleteClientModal(clientRegistration: ClientRegistrationPrivate): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Client';
    modalRef.componentInstance.entityName = clientRegistration.displayName;

    const clientId = clientRegistration.clientId;

    modalRef.result
        .then((confirmed: boolean) => {
            if (confirmed) {
                firstValueFrom(this.clientRegistrationService.deleteClientRegistration(clientId))
                    .then(() => {
                        this.toastService.show('Client deleted', 'The Client has been deleted successfully');
                        this.clientRegistrations = this.clientRegistrations.filter((v: ClientRegistrationPrivate) => v.clientId != clientId);
                    })
                    .catch((apiError: ApiError) => {
                        this.toastService.show('Client deletion failed', 'The Client deletion failed: ' + apiError.message);
                    })
            }
        })
        .catch(() => {});
  }
}
