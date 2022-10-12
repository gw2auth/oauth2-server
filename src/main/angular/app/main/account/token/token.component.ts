import {Component, Inject, OnDestroy, OnInit} from '@angular/core';
import {TokenService} from '../../../common/token.service';
import { faAngleDoubleDown, faAngleDoubleUp, faEdit, faTrashAlt, faCheck, faBan, faSave, faTimes } from '@fortawesome/free-solid-svg-icons';
import {catchError} from 'rxjs/operators';
import {firstValueFrom, of} from 'rxjs';
import {ToastService} from '../../../toast/toast.service';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {Token} from '../../../common/token.model';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {EditTokenComponent} from './edit-token.component';
import {ActivatedRoute} from '@angular/router';
import {WINDOW} from '../../../app.module';
import {MessageEventData, Type} from '../../../common/window.model';
import {DeleteTokenModalComponent} from './delete-token-modal.component';


@Component({
  selector: 'app-main-account-token',
  templateUrl: './token.component.html'
})
export class TokenComponent implements OnInit, OnDestroy {

  faAngleDoubleDown = faAngleDoubleDown;
  faAngleDoubleUp = faAngleDoubleUp;
  faEdit = faEdit;
  faTrashAlt = faTrashAlt;
  faCheck = faCheck;
  faBan = faBan;
  faSave = faSave;
  faTimes = faTimes;

  gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);
  tokensState: -1 | 0 | 1 = -1;
  tokens: Token[] = [];

  fragment: string | null = null;

  addTokenLoading = false;
  addTokenValue = '';

  constructor(private readonly tokenService: TokenService,
              private readonly toastService: ToastService,
              private readonly modalService: NgbModal,
              private readonly route: ActivatedRoute,
              @Inject(WINDOW) private readonly window: Window) {}

  ngOnInit(): void {
    this.tokenService.getTokens().subscribe((tokens) => {
        this.tokens = tokens;

        if (this.tokens.length > 0) {
            this.tokensState = 1;
        } else {
            this.tokensState = 0;
        }
    });
    this.route.fragment.subscribe((fragment) => this.fragment = fragment);
  }

  ngOnDestroy() {
    this.tokensState = -1;
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
                return firstValueFrom(this.tokenService.updateToken(token.gw2AccountId, updatedDisplayName, updatedApiToken));
            }
        })
        .then((updatedToken: Token) => {
            const index = this.tokens.findIndex((v: Token) => v.gw2AccountId == token.gw2AccountId)

            if (index == -1) {
                this.tokens.push(updatedToken);
            } else {
                this.tokens[index] = updatedToken;
            }

            this.toastService.show('API Token updated', 'The API Token has been updated successfully');
            this.sendNotificationToOpener(Type.UPDATE_TOKEN, updatedToken);
        })
        .catch((e) => {
            if (e) {
                if (e.error != undefined) {
                    this.toastService.show('API Token update failed', 'The API Token update failed: ' + e.error.message);
                } else {
                    this.toastService.show('API Token update failed', 'The API Token update failed for an unknown reason');
                }
            }
        });
  }

  openDeleteTokenModal(token: Token): void {
    const modalRef = this.modalService.open(DeleteTokenModalComponent);
    modalRef.componentInstance.entityName = token.displayName;
    modalRef.componentInstance.token = token;

    const gw2AccountId = token.gw2AccountId;
    modalRef.result
        .then((confirmed: boolean) => {
            if (confirmed) {
                return firstValueFrom(this.tokenService.deleteToken(gw2AccountId)).then(() => null);
            } else {
                return Promise.reject(false);
            }
        })
        .then((apiError: ApiError | null) => {
            if (apiError == null) {
                this.toastService.show('API Token deleted', 'The API Token has been deleted successfully');
                this.tokens = this.tokens.filter((v: Token) => v.gw2AccountId != gw2AccountId);

                if (this.tokens.length < 1) {
                    this.tokensState = 0;
                }

                this.sendNotificationToOpener(Type.DELETE_TOKEN, token);
            } else {
                this.toastService.show('API Token deletion failed', 'The API Token deletion failed: ' + apiError.message);
            }
        })
        .catch((e) => {
            if (e) {
                this.toastService.show('API Token deletion failed', 'The API Token deletion failed for an unknown reason');
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
                  this.toastService.show('API Token not added', 'Failed to add the API Token');
              } else {
                  this.toastService.show('API Token added', 'The API Token was added to your account successfully');
                  this.addTokenValue = '';
                  this.tokens.push(token);
                  this.tokensState = 1;

                  this.sendNotificationToOpener(Type.ADD_TOKEN, token);
              }
          });
  }

  sendNotificationToOpener(type: Type.ADD_TOKEN | Type.UPDATE_TOKEN | Type.DELETE_TOKEN, token: Token): void {
      if (this.window.opener != null) {
          this.window.opener.postMessage(new MessageEventData<Token>(type, token), this.window.location.origin);
      }
  }
}
