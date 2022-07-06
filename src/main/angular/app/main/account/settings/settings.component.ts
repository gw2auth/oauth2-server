import {Component, OnInit} from '@angular/core';
import {faGithub, faGoogle} from '@fortawesome/free-brands-svg-icons';
import {faQuestion, faTrashAlt} from '@fortawesome/free-solid-svg-icons';
import {AccountFederation, AccountFederations, AccountSession, AccountSessions} from './account.model';
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

  federations: AccountFederations | null = null;
  sessions: AccountSessions | null = null;

  constructor(private readonly accountService: AccountService, private readonly toastService: ToastService, private readonly modalService: NgbModal, private readonly authService: AuthService) { }

  ngOnInit(): void {
    this.accountService.getAccountFederations().subscribe((federations) => this.federations = federations);
    this.accountService.getAccountSessions().subscribe((sessions) => this.sessions = sessions);
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
    const current = this.federations!.currentAccountFederation;
    return federation.issuer == current.issuer && federation.idAtIssuer == current.idAtIssuer;
  }

  isCurrentSession(session: AccountSession): boolean {
    return session.id == this.sessions!.currentAccountSessionId;
  }

  openDeleteFederationModal(federation: AccountFederation): void {
    const issuer = federation.issuer;
    const idAtIssuer = federation.idAtIssuer;

    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'Login provider';
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
            this.toastService.show('Login provider deleted', 'The Login provider has been deleted successfully');

            const federations = this.federations!;
            federations.accountFederations = federations.accountFederations.filter((v) => !(v.issuer == issuer && v.idAtIssuer == idAtIssuer));

            return null;
          } else {
            return Promise.reject(false);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Login provider deletion failed', 'The Login provider deletion failed for an unknown reason');
          }
        });
  }

  openDeleteSessionModal(session: AccountSession): void {
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

            const sessions = this.sessions!;
            sessions.accountSessions = sessions.accountSessions.filter((v) => v.id != sessionId);

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
            this.toastService.show('Account deleted', 'Your Account has been deleted successfully');
            this.authService.logout();

            return null;
          } else {
            return Promise.reject(false);
          }
        })
        .catch((e) => {
          if (e) {
            this.toastService.show('Account deletion failed', 'The Account deletion failed for an unknown reason');
          }
        });
  }
}
