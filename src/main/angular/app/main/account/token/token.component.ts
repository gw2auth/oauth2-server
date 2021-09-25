import {Component, OnInit} from '@angular/core';
import {TokenService} from '../../../service/token.service';
import { faAngleDoubleDown, faAngleDoubleUp, faEdit, faTrashAlt, faCheck, faBan, faSave, faTimes } from '@fortawesome/free-solid-svg-icons';
import {catchError} from 'rxjs/operators';
import {of} from 'rxjs';
import {ToastService} from '../../../toast/toast.service';
import {ApiError, Gw2ApiPermission} from '../../../service/general.model';
import {Token} from '../../../service/token.model';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {EditTokenComponent} from './edit-token.component';
import {DeleteModalComponent} from '../../../general/delete-modal.component';
import {ActivatedRoute} from "@angular/router";


@Component({
  selector: 'app-main-account-token',
  templateUrl: './token.component.html',
  styleUrls: ['./token.component.scss']
})
export class TokenComponent implements OnInit {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;
  faEdit = faEdit;
  faTrashAlt = faTrashAlt;
  faCheck = faCheck;
  faBan = faBan;
  faSave = faSave;
  faTimes = faTimes;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);
  tokens: Token[] = [];

  fragment: string | null = null;

  addTokenLoading = false;
  addTokenValue = '';

  constructor(private readonly tokenService: TokenService, private readonly toastService: ToastService, private readonly modalService: NgbModal, private readonly route: ActivatedRoute) {}

  ngOnInit(): void {
    this.tokenService.getTokens().subscribe((tokens) => this.tokens = tokens);
    this.route.fragment.subscribe((fragment) => this.fragment = fragment);
  }

  openEditTokenModal(token: Token): void {
    const modalRef = this.modalService.open(EditTokenComponent);
    modalRef.componentInstance.setToken(token);

    modalRef.result
        .then((result) => {
            let updatedDisplayName: string | undefined = undefined;
            let updatedApiToken: string | undefined = undefined;

            if (result.displayName != token.displayName) {
                updatedDisplayName = result.displayName;
            }

            if (result.gw2ApiToken != '') {
                updatedApiToken = result.gw2ApiToken;
            }

            if (updatedDisplayName == undefined && updatedApiToken == undefined) {
                return Promise.reject(false);
            } else {
                return this.tokenService.updateToken(token.gw2AccountId, updatedDisplayName, updatedApiToken).toPromise();
            }
        })
        .then((updatedToken: Token) => {
            const index = this.tokens.findIndex((v: Token) => v.gw2AccountId == token.gw2AccountId)

            if (index == -1) {
                this.tokens.push(updatedToken);
            } else {
                this.tokens[index] = updatedToken;
            }

            this.toastService.show('API-Token updated', 'The API-Token has been updated successfully');
            this.sendNotificationToParent('UPDATE', updatedToken);
        })
        .catch((e) => {
            if (e) {
                if (e.error != undefined) {
                    this.toastService.show('API-Token update failed', 'The API-Token update failed: ' + e.error.message);
                } else {
                    this.toastService.show('API-Token update failed', 'The API-Token update failed for an unknown reason');
                }
            }
        });
  }

  openDeleteTokenModal(token: Token): void {
    const modalRef = this.modalService.open(DeleteModalComponent);
    modalRef.componentInstance.entityType = 'API-Token';
    modalRef.componentInstance.entityName = token.displayName;

    const gw2AccountId = token.gw2AccountId;

      modalRef.result
          .then((confirmed: boolean) => {
              if (confirmed) {
                  return this.tokenService.deleteToken(gw2AccountId).toPromise().then(() => null);
              } else {
                  return Promise.reject(false);
              }
          })
          .then((apiError: ApiError | null) => {
              if (apiError == null) {
                  this.toastService.show('API-Token deleted', 'The API-Token has been deleted successfully');
                  this.tokens = this.tokens.filter((v: Token) => v.gw2AccountId != gw2AccountId);

                  this.sendNotificationToParent('DELETE', token);
              } else {
                  this.toastService.show('API-Token deletion failed', 'The API-Token deletion failed: ' + apiError.message);
              }
          })
          .catch((e) => {
              if (e) {
                  this.toastService.show('API-Token deletion failed', 'The API-Token deletion failed for an unknown reason');
              }
          });
  }

  onAddTokenClick(): void {
    this.addTokenLoading = true;

      this.tokenService.createToken(this.addTokenValue)
          .pipe(catchError((e) => of(null)))
          .subscribe((token) => {
              this.addTokenLoading = false;

              if (token == null) {
                  this.toastService.show('API-Token not added', 'Failed to add the API-Token');
              } else {
                  this.toastService.show('API-Token added', 'The API-Token was added to your account successfully');
                  this.addTokenValue = '';
                  this.tokens.push(token);

                  this.sendNotificationToParent('ADD', token);
              }
          });
  }

  sendNotificationToParent(type: string, token: Token): void {
      if (window.opener != null) {
          window.parent.postMessage({type: type, token: token}, location.origin);
      }
  }
}
