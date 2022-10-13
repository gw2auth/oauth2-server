import {Component, Input} from '@angular/core';
import {NgbActiveModal, NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {faTrashAlt, faTimes} from '@fortawesome/free-solid-svg-icons';
import {ClientAuthorization} from './client-authorization.model';
import {ApiError, Gw2ApiPermission} from '../../../common/common.model';
import {ClientRegistrationPublic} from '../client/client-registration.model';
import {DeleteAuthorizationModalComponent} from './delete-authorization-modal.component';
import {ClientAuthorizationService} from './client-authorization.service';
import {ToastService} from '../../../toast/toast.service';
import { firstValueFrom } from 'rxjs';


@Component({
    selector: 'app-authorization-modal',
    template: `
        <div class="modal-header">
            <h5 class="modal-title">Authorization {{clientAuthorization.displayName}}</h5>
            <button type="button" class="btn btn-sm" (click)="dismiss()" aria-label="Close"><fa-icon [icon]="faTimes"></fa-icon></button>
        </div>
        <div class="modal-body">
            <div class="container-fluid p-2">
                <div class="row row-cols-1 g-3">
                    <div class="col">
                        <label [htmlFor]="'creationTime'" class="form-label">Created at</label>
                        <input type="text" class="form-control" [id]="'creationTime'" [(ngModel)]="clientAuthorization.creationTime" name="creationTime" disabled />
                    </div>
                    <div class="col">
                        <label [htmlFor]="'lastUpdateTime'" class="form-label">Last updated at</label>
                        <input type="text" class="form-control" [id]="'creationTime'" [(ngModel)]="clientAuthorization.lastUpdateTime" name="lastUpdateTime" disabled />
                    </div>
                    <div class="col">
                        <label [htmlFor]="'authorizationAuthorizedGw2ApiPermissions'" class="form-label">Permissions</label>
                        <div class="container-fluid" [id]="'authorizationAuthorizedGw2ApiPermissions'">
                            <div class="row row-cols-2 row-cols-md-3 g-2">
                                <ng-container *ngFor="let gw2ApiPermission of gw2ApiPermissions">
                                    <div class="col">
                                        <app-gw2-api-permission-badge [gw2ApiPermission]="gw2ApiPermission" [isPresent]="clientAuthorization.authorizedGw2ApiPermissions.includes(gw2ApiPermission)"></app-gw2-api-permission-badge>
                                    </div>
                                </ng-container>
                            </div>
                        </div>
                    </div>
                    <div class="col">
                        <label [htmlFor]="'authorizationAuthorizedVerifiedInformation'" class="form-label">Read account verification</label>
                        <input type="text" class="form-control" [id]="'authorizationAuthorizedVerifiedInformation'" [value]="clientAuthorization.authorizedVerifiedInformation ? 'Yes' : 'No'" [attr.aria-describedby]="'authorizationAuthorizedVerifiedInformationDescription'" disabled />
                        <div [id]="'authorizationAuthorizedVerifiedInformationDescription'" class="form-text">If yes, the application can read your account verification status for the linked API Tokens</div>
                    </div>
                    <div class="col">
                        <label [htmlFor]="'tokens'" class="form-label">API Tokens</label>
                        <div class="list-group" [id]="'tokens'" [attr.aria-describedby]="'tokensDescription'">
                            <a *ngFor="let token of clientAuthorization.tokens" [routerLink]="['', 'account', 'token']" [fragment]="token.gw2AccountId" class="list-group-item list-group-item-action">
                                {{token.displayName}}
                            </a>
                        </div>
                        <div [id]="'tokensDescription'" class="form-text">The application receives subtokens which are created using the authorized API Tokens. It will never receive your actual API Token. Subtokens are short-lived API Tokens with reduced permissions</div>
                    </div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-accent-inner" (click)="dismiss()"><fa-icon [icon]="faTimes"></fa-icon> Close</button>
            <button type="button" class="btn btn-danger" (click)="onDeleteClick()"><fa-icon [icon]="faTrashAlt"></fa-icon> Delete</button>
        </div>
    `
})
export class AuthorizationModalComponent {

    faTrashAlt = faTrashAlt;
    faTimes = faTimes;

    gw2ApiPermissions: Gw2ApiPermission[] = Object.values(Gw2ApiPermission);

    @Input('clientRegistration') clientRegistration!: ClientRegistrationPublic;
    @Input('clientAuthorization') clientAuthorization!: ClientAuthorization;

    constructor(private readonly activeModal: NgbActiveModal,
                private readonly modalService: NgbModal,
                private readonly clientAuthorizationService: ClientAuthorizationService,
                private readonly toastService: ToastService) {}

    dismiss(): void {
        this.activeModal.dismiss(false);
    }

    onDeleteClick(): void {
        const modalRef = this.modalService.open(DeleteAuthorizationModalComponent);
        modalRef.componentInstance.entityName = this.clientAuthorization.displayName;

        const id = this.clientAuthorization.id;

        modalRef.result
            .then((confirmed: boolean) => {
                if (confirmed) {
                    return firstValueFrom(this.clientAuthorizationService.deleteClientAuthorization(id)).then(() => null);
                } else {
                    return Promise.reject(false);
                }
            })
            .then((apiError: ApiError | null) => {
                if (apiError == null) {
                    this.toastService.show('Authorization deleted', 'The Authorization has been deleted successfully');
                    this.activeModal.close(true);
                } else {
                    this.toastService.show('Authorization deletion failed', 'The Authorization deletion failed: ' + apiError.message);
                }
            })
            .catch((e) => {
                if (e) {
                    this.toastService.show('Authorization deletion failed', 'The Authorization deletion failed for an unknown reason');
                }
            });
    }

    close(): void {
        this.activeModal.close(false);
    }
}