import {Component} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import {faSave, faTimes} from '@fortawesome/free-solid-svg-icons';
import {Token} from '../../../common/token.model';


@Component({
    selector: 'app-main-account-token',
    template: `
        <div class="modal-header">
            <h5 class="modal-title">Edit {{currentDisplayName}}</h5>
            <button type="button" class="btn btn-sm" (click)="dismiss()" aria-label="Close"><fa-icon [icon]="faTimes"></fa-icon></button>
        </div>
        <div class="modal-body">
            <form>
                <div class="mb-3">
                    <label [htmlFor]="'edit-api-token-modal-display-name'" class="form-label">Name</label>
                    <input type="text" class="form-control" [id]="'edit-api-token-modal-display-name'" [(ngModel)]="displayName" name="displayName" />
                </div>

                <div class="mb-3">
                    <label [htmlFor]="'edit-api-token-modal-api-token'" class="form-label">API Token</label>
                    <input type="text" class="form-control" [id]="'edit-api-token-modal-api-token'" [attr.aria-describedby]="'edit-api-token-modal-api-token-description'" [(ngModel)]="gw2ApiToken" name="gw2ApiToken" />
                    <div [id]="'edit-api-token-modal-api-token-description'" class="form-text">The API Token must be linked to the same Guild Wars 2 Account as the current API Token.</div>
                </div>
            </form>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-accent-inner" (click)="dismiss()"><fa-icon [icon]="faTimes"></fa-icon> Cancel</button>
            <button type="button" class="btn btn-primary" (click)="close()"><fa-icon [icon]="faSave"></fa-icon> Save</button>
        </div>
    `
})
export class EditTokenComponent {

    faSave = faSave;
    faTimes = faTimes;

    currentDisplayName = '';
    displayName = '';
    gw2ApiToken = '';

    constructor(private readonly activeModal: NgbActiveModal) {}

    setToken(token: Token) {
        this.currentDisplayName = token.displayName;
        this.displayName = token.displayName;
    }

    dismiss(): void {
        this.activeModal.dismiss();
    }

    close(): void {
        this.activeModal.close({displayName: this.displayName, gw2ApiToken: this.gw2ApiToken});
    }
}