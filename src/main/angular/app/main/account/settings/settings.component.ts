import {Component, OnInit} from '@angular/core';
import {faGithub, faGoogle} from '@fortawesome/free-brands-svg-icons';
import {faQuestion, faTrashAlt, faAngleDoubleDown, faAngleDoubleUp} from '@fortawesome/free-solid-svg-icons';
import {AccountFederation, AccountFederations, AccountFederationSession} from './account.model';
import {AccountService} from './account.service';
import {IconProp} from '@fortawesome/fontawesome-svg-core';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {ToastService} from '../../../toast/toast.service';
import {AuthService} from '../../../auth.service';
import {firstValueFrom} from 'rxjs';


@Component({
  selector: 'app-settings',
  templateUrl: './settings.component.html'
})
export class SettingsComponent implements OnInit {

  faGithub = faGithub;
  faGoogle = faGoogle;
  faQuestion = faQuestion;
  faTrashAlt = faTrashAlt;
  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;

  federations: AccountFederations | null = null;

  constructor(private readonly accountService: AccountService, private readonly toastService: ToastService, private readonly modalService: NgbModal, private readonly authService: AuthService) { }

  ngOnInit(): void {
    this.accountService.getAccountFederations().subscribe((federations) => this.federations = federations);
  }

  getIssuerName(issuer: string): string {
    switch (issuer) {
      case 'github': return 'GitHub';
      case 'google': return 'Google';
      case 'cognito': return 'GW2Auth';
      default: return 'Unknown';
    }
  }

  getIssuerIcon(issuer: string): IconProp {
    switch (issuer) {
      case 'github': return this.faGithub;
      case 'google': return this.faGoogle;
      default: return this.faQuestion;
    }
  }

  isCurrentFederation(federation: AccountFederation): boolean {
    return federation.issuer == this.federations!.currentIssuer && federation.idAtIssuer == this.federations!.currentIdAtIssuer;
  }

  isCurrentSession(session: AccountFederationSession): boolean {
    return session.id == this.federations!.currentSessionId;
  }

  openDeleteFederationModal(federation: AccountFederation): void {
    const issuer = federation.issuer;
    const idAtIssuer = federation.idAtIssuer;

    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Login Provider';
    modalRef.componentInstance.entityName = this.getIssuerName(federation.issuer) + ' - ' + federation.idAtIssuer;

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return firstValueFrom(this.accountService.deleteAccountFederation(issuer, idAtIssuer)).then(() => true);
          } else {
            return Promise.reject(false);
          }
        })
        .then((success) => {
          if (success) {
            this.toastService.show('Login provider deleted', 'The login provider has been deleted successfully');

            this.federations!.federations = this.federations!.federations.filter((v) => !(v.issuer == issuer && v.idAtIssuer == idAtIssuer));

            return null;
          } else {
            return Promise.reject(false);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Login provider deletion failed', 'The login provider deletion failed for an unknown reason');
          }
        });
  }

  openDeleteSessionModal(session: AccountFederationSession): void {
    const sessionId = session.id;

    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Session';
    modalRef.componentInstance.entityName = 'ID ' + sessionId.substring(0, 10);

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return firstValueFrom(this.accountService.deleteAccountSession(sessionId)).then(() => true)
          } else {
            return Promise.reject(false);
          }
        })
        .then((success) => {
          if (success) {
            this.toastService.show('Session deleted', 'The session has been deleted successfully');

            for (let federation of this.federations!.federations) {
              federation.sessions = federation.sessions.filter((v) => v.id != sessionId);
            }

            return null;
          } else {
            return Promise.reject(false);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Session deletion failed', 'The session deletion failed for an unknown reason');
          }
        });
  }

  openDeleteAccountModal(): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Account';
    modalRef.componentInstance.entityName = 'your account';

    modalRef.result
        .then((confirmed: boolean) => {
          if (confirmed) {
            return firstValueFrom(this.accountService.deleteAccount());
          } else {
            return Promise.reject(false);
          }
        })
        .then((success) => {
          if (success) {
            this.toastService.show('Account deleted', 'Your account has been deleted successfully');
            this.authService.logout();

            return null;
          } else {
            return Promise.reject(false);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Account deletion failed', 'The account deletion failed for an unknown reason');
          }
        });
  }
}
