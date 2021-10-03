import { Component, OnInit } from '@angular/core';
import {ClientAuthorizationService} from './client-authorization.service';
import {ClientAuthorization, ClientAuthorizationLog, Token} from './client-authorization.model';
import {faTrashAlt, faAngleDoubleDown, faAngleDoubleUp} from '@fortawesome/free-solid-svg-icons';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {ToastService} from '../../../toast/toast.service';
import {ClientRegistrationPublic} from '../client/client-registration.model';
import {ActivatedRoute} from '@angular/router';


class InternalClientAuthorization {

  clientRegistration: ClientRegistrationPublic;
  accountSub: string;
  authorizedGw2ApiPermissions: Gw2ApiPermission[];
  tokens: Token[];
  logs: ClientAuthorizationLog[];
  nextLogPage: number;

  constructor(clientAuthorization: ClientAuthorization) {
    this.clientRegistration = clientAuthorization.clientRegistration;
    this.accountSub = clientAuthorization.accountSub;
    this.authorizedGw2ApiPermissions = clientAuthorization.authorizedGw2ApiPermissions;
    this.tokens = clientAuthorization.tokens;
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

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);
  clientAuthorizations: InternalClientAuthorization[] = [];

  fragment: string | null = null;

  constructor(private readonly clientAuthorizationService: ClientAuthorizationService,
              private readonly modalService: NgbModal,
              private readonly toastService: ToastService,
              private readonly route: ActivatedRoute) { }

  ngOnInit(): void {
    this.clientAuthorizationService.getClientAuthorizations().subscribe((clientAuthorizations) => {
      this.clientAuthorizations = clientAuthorizations.map((v) => new InternalClientAuthorization(v));
    });

    this.route.fragment.subscribe((fragment) => this.fragment = fragment);
  }

  isCurrentlyActive(date: Date): boolean {
    return date.getTime() > Date.now();
  }

  openDeleteClientAuthorizationModal(clientAuthorization: ClientAuthorization): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Application';
    modalRef.componentInstance.entityName = clientAuthorization.clientRegistration.displayName;

    const clientId = clientAuthorization.clientRegistration.clientId;

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return this.clientAuthorizationService.deleteClientAuthorization(clientId).toPromise().then(() => null);
          } else {
            return Promise.reject(false);
          }
        })
        .then((apiError: ApiError | null) => {
          if (apiError == null) {
            this.toastService.show('Application authorization deleted', 'The Application authorization has been deleted successfully');
            this.clientAuthorizations = this.clientAuthorizations.filter((v: ClientAuthorization) => v.clientRegistration.clientId != clientId);
          } else {
            this.toastService.show('Application authorization deletion failed', 'The Application authorization deletion failed: ' + apiError.message);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Application authorization deletion failed', 'The Application authorization deletion failed for an unknown reason');
          }
        });
  }

  onLoadNextLogPageClick(clientAuthorization: InternalClientAuthorization): void {
    const nextLogPage = clientAuthorization.nextLogPage;
    clientAuthorization.nextLogPage = -1;

    this.clientAuthorizationService.getClientAuthorizationLogs(clientAuthorization.clientRegistration.clientId, nextLogPage).subscribe((clientAuthorizationLogs) => {
      clientAuthorization.nextLogPage = clientAuthorizationLogs.nextPage;
      clientAuthorization.logs.push(...clientAuthorizationLogs.logs);
    });
  }
}
