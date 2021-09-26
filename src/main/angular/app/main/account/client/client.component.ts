import {Component, OnInit} from '@angular/core';
import {ClientRegistrationService} from './client-registration.service';
import {AuthorizationGrantType, ClientRegistrationPrivate, authorizationGrantTypeDisplayName} from './client-registration.model';
import {faAngleDoubleDown, faAngleDoubleUp, faTrashAlt, faCopy} from '@fortawesome/free-solid-svg-icons';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {ToastService} from '../../../toast/toast.service';
import {ApiError} from '../../../service/general.model';


@Component({
  selector: 'app-client',
  templateUrl: './client.component.html',
  styleUrls: ['./client.component.scss']
})
export class ClientComponent implements OnInit {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;
  faTrashAlt = faTrashAlt;
  faCopy = faCopy;

  clientRegistrations: ClientRegistrationPrivate[] = [];

  constructor(private readonly clientRegistrationService: ClientRegistrationService, private readonly modalService: NgbModal, private readonly toastService: ToastService) { }

  ngOnInit(): void {
    this.clientRegistrationService.getClientRegistrations().subscribe((clientRegistrations) => this.clientRegistrations = clientRegistrations);
  }

  authorizationGrantTypeDisplayName(authorizationGrantType: AuthorizationGrantType): string {
    return authorizationGrantTypeDisplayName(authorizationGrantType);
  }

  openDeleteClientModal(clientRegistration: ClientRegistrationPrivate): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Client';
    modalRef.componentInstance.entityName = clientRegistration.displayName;

    const clientId = clientRegistration.clientId;

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return this.clientRegistrationService.deleteClientRegistration(clientId).toPromise().then(() => null);
          } else {
            return Promise.reject();
          }
        })
        .then((apiError: ApiError | null) => {
            if (apiError == null) {
                this.toastService.show('Client deleted', 'The Client has been deleted successfully');
                this.clientRegistrations = this.clientRegistrations.filter((v: ClientRegistrationPrivate) => v.clientId != clientId);
            } else {
                this.toastService.show('Client deletion failed', 'The Client deletion failed: ' + apiError.message);
            }
        })
        .catch((e) => {
          console.log(e);
          this.toastService.show('Client deletion failed', 'The Client deletion failed for an unknown reason');
        });
  }
}
