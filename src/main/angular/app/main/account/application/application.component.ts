import { Component, OnInit } from '@angular/core';
import {ClientConsentService} from './client-consent.service';
import {
  ClientConsent,
  tryGetLogType
} from './client-consent.model';
import {faTrashAlt, faAngleDoubleDown, faAngleDoubleUp, faUserShield} from '@fortawesome/free-solid-svg-icons';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {ToastService} from '../../../toast/toast.service';
import {ClientRegistrationPublic} from '../client/client-registration.model';
import {ActivatedRoute} from '@angular/router';
import {DeleteApplicationModalComponent} from './delete-application-modal.component';
import {ClientAuthorization} from './client-authorization.model';
import {ClientAuthorizationService} from './client-authorization.service';
import {AuthorizationModalComponent} from './authorization-modal.component';
import {firstValueFrom} from 'rxjs';
import {AccountLog} from '../../../common/account-log.model';


class InternalClientConsent {

  clientRegistration: ClientRegistrationPublic;
  accountSub: string;
  authorizedGw2ApiPermissions: Gw2ApiPermission[];
  authorizedVerifiedInformation: boolean;
  clientAuthorizationsState: -1 | 0 | 1 = 0;// loading, initial, loaded
  clientAuthorizations: ClientAuthorization[] = [];
  logs: AccountLog[];
  nextLogPage: number;

  constructor(clientAuthorization: ClientConsent) {
    this.clientRegistration = clientAuthorization.clientRegistration;
    this.accountSub = clientAuthorization.accountSub;
    this.authorizedGw2ApiPermissions = clientAuthorization.authorizedGw2ApiPermissions;
    this.authorizedVerifiedInformation = clientAuthorization.authorizedVerifiedInformation;
    this.logs = [];
    this.nextLogPage = 0;
  }
}


@Component({
  selector: 'app-application',
  templateUrl: './application.component.html'
})
export class ApplicationComponent implements OnInit {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;
  faTrashAlt = faTrashAlt;
  faUserShield = faUserShield;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);
  clientConsents: InternalClientConsent[] = [];

  fragment: string | null = null;

  constructor(private readonly clientConsentService: ClientConsentService,
              private readonly clientAuthorizationService: ClientAuthorizationService,
              private readonly modalService: NgbModal,
              private readonly toastService: ToastService,
              private readonly route: ActivatedRoute) { }

  ngOnInit(): void {
    this.clientConsentService.getClientConsents().subscribe((clientConsents) => {
      this.clientConsents = clientConsents.map((v) => new InternalClientConsent(v));
    });

    this.route.fragment.subscribe((fragment) => this.fragment = fragment);
  }

  tryGetLogType(log: AccountLog): string {
    return tryGetLogType(log);
  }

  openDeleteClientConsentModal(clientConsent: InternalClientConsent): void {
    const modalRef = this.modalService.open(DeleteApplicationModalComponent);
    modalRef.componentInstance.entityName = clientConsent.clientRegistration.displayName;

    const clientId = clientConsent.clientRegistration.clientId;

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return firstValueFrom(this.clientConsentService.deleteClientConsent(clientId)).then(() => null);
          } else {
            return Promise.reject(false);
          }
        })
        .then((apiError: ApiError | null) => {
          if (apiError == null) {
            this.toastService.show('Application deleted', 'The application consent has been deleted successfully');
            this.clientConsents = this.clientConsents.filter((v: ClientConsent) => v.clientRegistration.clientId != clientId);
          } else {
            this.toastService.show('Application deletion failed', 'The application consent deletion failed: ' + apiError.message);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Application deletion failed', 'The application consent deletion failed for an unknown reason');
          }
        });
  }

  onLoadClientAuthorizationsClick(clientConsent: InternalClientConsent): void {
    if (clientConsent.clientAuthorizationsState == 0) {
      clientConsent.clientAuthorizationsState = -1;

      this.clientAuthorizationService.getClientAuthorizations(clientConsent.clientRegistration.clientId).subscribe((clientAuthorizations) => {
        clientConsent.clientAuthorizations = clientAuthorizations;
        clientConsent.clientAuthorizationsState = 1;
      });
    }
  }

  openClientAuthorizationModal(clientConsent: InternalClientConsent, clientAuthorization: ClientAuthorization): void {
    const modalRef = this.modalService.open(AuthorizationModalComponent);
    modalRef.componentInstance.clientRegistration = clientConsent.clientRegistration;
    modalRef.componentInstance.clientAuthorization = clientAuthorization;

    modalRef.result.then((wasDeleted) => {
      if (wasDeleted) {
        clientConsent.clientAuthorizations = clientConsent.clientAuthorizations.filter((v: ClientAuthorization) => v.id != clientAuthorization.id);
      }
    });
  }

  onLoadNextLogPageClick(clientConsent: InternalClientConsent): void {
    const nextLogPage = clientConsent.nextLogPage;

    if (nextLogPage >= 0) {
      clientConsent.nextLogPage = -2;

      firstValueFrom(this.clientConsentService.getClientConsentLogs(clientConsent.clientRegistration.clientId, nextLogPage))
          .then((clientConsentLogs) => {
            clientConsent.nextLogPage = clientConsentLogs.nextPage;
            clientConsent.logs.push(...clientConsentLogs.logs);
          })
          .catch((e) => {
            clientConsent.nextLogPage = nextLogPage;
          });
    }
  }
}
